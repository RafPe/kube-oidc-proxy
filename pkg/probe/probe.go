// Copyright Jetstack Ltd. See LICENSE for details.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/heptiolabs/healthcheck"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/klog/v2"
)

const (
	timeout = time.Second * 10
)

// transientMarkers are substrings that unambiguously identify a transient
// network/timeout failure while probing an issuer. The set is deliberately
// conservative: a false "pending" is worse than a false "ready" here, because
// in require-all mode a healthy issuer wrongly classified as pending would keep
// the pod from ever becoming ready. Only phrases that cannot appear in an
// ordinary JWT verification error belong here.
var transientMarkers = []string{
	"context deadline exceeded",
	"connection refused",
	"no such host",
	"i/o timeout",
}

// IssuerReadiness pairs an issuer with the fake JWT used to probe whether
// its authenticator has completed JWKS initialization.
type IssuerReadiness struct {
	IssuerURL string
	FakeJWT   string
}

type HealthCheck struct {
	handler    healthcheck.Handler
	oidcAuther authenticator.Token
	issuers    []IssuerReadiness
	requireAll bool

	mu          sync.Mutex
	ready       bool
	initialized map[string]bool
}

func Run(port string, issuers []IssuerReadiness, requireAll bool, oidcAuther authenticator.Token) error {
	h := &HealthCheck{
		handler:     healthcheck.NewHandler(),
		oidcAuther:  oidcAuther,
		issuers:     issuers,
		requireAll:  requireAll,
		initialized: make(map[string]bool),
	}

	h.handler.AddReadinessCheck("secure serving", h.Check)

	// Bind synchronously so a failure to acquire the port is surfaced to the
	// caller at startup rather than being swallowed inside the goroutine.
	ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
	if err != nil {
		return fmt.Errorf("readiness probe failed to listen on port %s: %w", port, err)
	}

	go func() {
		if err := http.Serve(ln, h.handler); err != nil {
			klog.Errorf("ready probe listener failed: %s", err)
		}
	}()

	return nil
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
	msg := err.Error()
	for _, marker := range transientMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// Check probes every issuer that has not yet been observed as initialized,
// logs per-issuer transitions and any still-pending issuers, and reports
// readiness. Once readiness latches (via ready.Store(true)) it always
// returns nil, but probing and pending-issuer logging continue on every
// call so operators keep seeing progress for issuers that initialize late.
func (h *HealthCheck) Check() error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	h.mu.Lock()
	defer h.mu.Unlock()

	var pending []string
	for _, issuer := range h.issuers {
		if h.initialized[issuer.IssuerURL] {
			continue
		}

		_, _, err := h.oidcAuther.AuthenticateToken(ctx, issuer.FakeJWT)
		// The issuer counts as initialized only once its authenticator reaches
		// token verification. A "not initialized" signal (JWKS not fetched yet)
		// or a transient network/timeout error both leave it pending; check
		// "not initialized" first since it is the more specific signal.
		if err != nil && (isNotInitialized(err) || isTransient(err)) {
			pending = append(pending, issuer.IssuerURL)
			continue
		}

		h.initialized[issuer.IssuerURL] = true
		klog.Infof("OIDC issuer initialized: %s (%d/%d ready)", issuer.IssuerURL, len(h.initialized), len(h.issuers))
	}

	if len(pending) > 0 {
		klog.Infof("readiness: %d/%d OIDC issuers initialized, pending: %v",
			len(h.initialized), len(h.issuers), pending)
	}

	if h.ready {
		return nil
	}

	if h.requireAll && len(pending) > 0 {
		return errors.New("OIDC providers not yet initialized")
	}
	if !h.requireAll && len(h.initialized) == 0 {
		return errors.New("no OIDC provider initialized yet")
	}

	h.ready = true
	klog.V(4).Info("OIDC provider(s) initialized, marking ready.")
	return nil
}
