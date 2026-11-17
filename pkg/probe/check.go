// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"syscall"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// pendingIssuer is one issuer that failed its probe, with the classification
// of why. The reason is part of the state the pending record reports on
// change: an issuer that moves from unreachable to still-initializing is a
// change an operator wants to see.
type pendingIssuer struct {
	issuerURL string
	reason    pendingReason
}

// isNotInitialized reports whether err indicates the issuer's authenticator has
// not yet completed JWKS initialization. It matches on the stable "not
// initialized" fragment so both upstream phrasings ("authenticator not
// initialized" and "... is not initialized") are handled.
func isNotInitialized(err error) bool {
	return strings.Contains(err.Error(), "not initialized")
}

// isTransient reports whether err is a transient network/timeout failure. Such
// errors must leave the issuer pending rather than latching it as initialized,
// otherwise a momentary hiccup would be mistaken for a fetched JWKS.
func isTransient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// The issuer is not listening yet, or its name does not resolve yet: both
	// are what a cold cluster looks like while the issuer is still coming up.
	var dnsErr *net.DNSError
	return errors.Is(err, syscall.ECONNREFUSED) || errors.As(err, &dnsErr)
}

// classifyPending classifies the error from an issuer probe. "not_initialized"
// is the authenticator saying its JWKS is not fetched yet and "transient" a
// network or timeout failure; both leave the issuer pending. Any other error
// was raised at verification of the fake token, which means the JWKS loaded,
// so it returns pending=false and the issuer counts as initialized.
func classifyPending(err error) (reason pendingReason, pending bool) {
	switch {
	case isNotInitialized(err):
		return pendingNotInitialized, true
	case isTransient(err):
		return pendingTransient, true
	default:
		return "", false
	}
}

// check reports readiness. It first requires the proxy to be serving, then
// probes every issuer that has not yet been observed as initialized, logging
// per-issuer transitions and any still-pending issuers. Once readiness latches
// (s.ready is set true under s.mu) it always returns nil, but probing and
// pending-issuer logging continue on every call so operators keep seeing
// progress for issuers that initialize late.
func (s *Server) check() error {
	// Checked first: it is cheap, and it is the more fundamental condition. An
	// initialized issuer on a process that is not yet answering requests is not
	// readiness — advertising it would put the pod into its Service while
	// requests could only queue.
	if !s.serving.Load() {
		return errors.New("proxy is not yet serving")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Snapshot the issuers still needing a probe under the lock, then release it
	// so the potentially slow AuthenticateToken calls run lock-free. No blocking
	// authenticator call may run while s.mu is held (#53).
	s.mu.Lock()
	toProbe := make([]issuerReadiness, 0, len(s.issuers))
	for _, issuer := range s.issuers {
		if !s.initialized[issuer.issuerURL] {
			toProbe = append(toProbe, issuer)
		}
	}
	s.mu.Unlock()

	// Probe each not-yet-initialized issuer without holding the lock.
	var newlyInitialized []string
	var pending []pendingIssuer
	for _, issuer := range toProbe {
		// The issuer counts as initialized only once its authenticator reaches
		// token verification, which the fake token always fails.
		if _, _, err := s.oidcAuthenticator.AuthenticateToken(ctx, issuer.fakeJWT); err != nil {
			if reason, isPending := classifyPending(err); isPending {
				pending = append(pending, pendingIssuer{issuerURL: issuer.issuerURL, reason: reason})
				continue
			}
		}
		newlyInitialized = append(newlyInitialized, issuer.issuerURL)
	}

	// Re-acquire the lock to record results and evaluate readiness.
	s.mu.Lock()
	defer s.mu.Unlock()

	pending = s.recordProbeResults(ctx, newlyInitialized, pending)

	if s.ready {
		return nil
	}

	if s.mode == ReadinessAll && len(pending) > 0 {
		return errors.New("OIDC providers not yet initialized")
	}
	if s.mode != ReadinessAll && len(s.initialized) == 0 {
		return errors.New("no OIDC provider initialized yet")
	}

	s.ready = true
	s.metrics.SetReady(true)
	logging.Emit(ctx, s.readinessLogger, logging.EventReadinessProxyReady,
		slog.Int("ready_issuers", len(s.initialized)),
		slog.Int("total_issuers", len(s.issuers)),
		slog.String("readiness_mode", string(s.mode)))
	return nil
}

// recordProbeResults records the outcome of one probe round: it marks the newly
// initialized issuers, publishes their records, and reports the pending set on
// change. It returns the pending results still current, which readiness is
// then evaluated against. A pending result for an issuer another check has
// initialized in the meantime is stale (both checks snapshotted it as
// uninitialized, the other answered first) and is dropped, so the newest record
// for that issuer stays the initialized one and readiness is not held back by
// it. The caller holds s.mu.
func (s *Server) recordProbeResults(ctx context.Context, newlyInitialized []string, pending []pendingIssuer) []pendingIssuer {
	for _, issuerURL := range newlyInitialized {
		if s.initialized[issuerURL] {
			continue
		}
		s.initialized[issuerURL] = true
		s.metrics.SetIssuerInitialized(authn.IssuerName(issuerURL), true)
		logging.Emit(ctx, s.oidcLogger, logging.EventOIDCIssuerInitialized,
			slog.String("issuer_name", authn.IssuerName(issuerURL)),
			slog.String("issuer_state", string(issuerInitialized)),
			slog.Int("ready_issuers", len(s.initialized)),
			slog.Int("total_issuers", len(s.issuers)))
	}

	// Drop results made stale by a concurrent check that initialized the
	// issuer between this check's snapshot and now.
	pending = slices.DeleteFunc(pending, func(p pendingIssuer) bool {
		return s.initialized[p.issuerURL]
	})

	// Report only on change, and record the new state either way so that a
	// pending set which clears and later recurs is reported again. The reason
	// is part of the state: an issuer moving from unreachable to still
	// initializing is a change worth a record.
	if key := pendingKey(pending); key != s.lastPending {
		for _, p := range pending {
			logging.Emit(ctx, s.oidcLogger, logging.EventOIDCIssuerPending,
				slog.String("issuer_name", authn.IssuerName(p.issuerURL)),
				slog.String("issuer_state", string(issuerPending)),
				slog.String("pending_reason", string(p.reason)),
				slog.Int("ready_issuers", len(s.initialized)),
				slog.Int("total_issuers", len(s.issuers)))
		}
		s.lastPending = key
	}

	return pending
}

// pendingKey renders the pending set as a comparable string so an unchanged
// set is not restated on every kubelet probe. The probe order follows the
// configured issuer order, so no sort is needed.
func pendingKey(pending []pendingIssuer) string {
	parts := make([]string, len(pending))
	for i, p := range pending {
		parts[i] = p.issuerURL + "=" + string(p.reason)
	}
	return strings.Join(parts, ",")
}
