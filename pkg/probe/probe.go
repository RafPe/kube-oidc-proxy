// Copyright Jetstack Ltd. See LICENSE for details.

// Package probe implements the proxy's readiness and liveness HTTP endpoints,
// reporting readiness once the proxy is serving and the configured OIDC
// issuers' authenticators have completed initialization.
package probe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/httpserve"
)

const (
	// timeout bounds one readiness check's issuer probes. It stays inside
	// httpserve.WriteTimeout so the 503 a slow check writes reaches the
	// kubelet.
	timeout = time.Second * 10

	// shutdownTimeout bounds the graceful shutdown of the readiness server so a
	// stuck connection cannot block process teardown indefinitely.
	shutdownTimeout = time.Second * 5
)

// pendingReason classifies why an issuer is not yet initialized. Its constants
// are the closed pending_reason value set carried by the oidc.issuer.pending
// record.
type pendingReason string

const (
	pendingNotInitialized pendingReason = "not_initialized"
	pendingTransient      pendingReason = "transient"
)

// issuerState is the closed issuer_state value set carried by the per-issuer
// records.
type issuerState string

const (
	issuerInitialized issuerState = "initialized"
	issuerPending     issuerState = "pending"
)

// ReadinessMode is the closed readiness_mode value set carried by the startup
// and readiness records: whether readiness waits for any one issuer or for all
// of them.
type ReadinessMode string

const (
	ReadinessAny ReadinessMode = "any"
	ReadinessAll ReadinessMode = "all"
)

// ReadinessModeFor renders --readiness-require-all-issuers as its
// readiness_mode. It lives here because the probe is what the flag configures.
func ReadinessModeFor(requireAll bool) ReadinessMode {
	if requireAll {
		return ReadinessAll
	}
	return ReadinessAny
}

// pendingIssuer is one issuer that failed its probe, with the classification
// of why. The reason is part of the state the pending record reports on
// change: an issuer that moves from unreachable to still-initializing is a
// change an operator wants to see.
type pendingIssuer struct {
	issuerURL string
	reason    pendingReason
}

// IssuerReadiness pairs an issuer with the fake JWT used to probe whether
// its authenticator has completed JWKS initialization.
type IssuerReadiness struct {
	IssuerURL string
	FakeJWT   string
}

// fakeJWTKey signs the probe token. The token is meant to fail verification:
// what the probe reads is how the authenticator refuses it, which tells an
// issuer still fetching its keys from one that has them. Nothing trusts this
// key, so it need not be secret.
var fakeJWTKey = []byte("this-is-a-32-byte-long-secret-key!!!!")

// fakeJWTHeader is the probe token's JOSE header, base64url-encoded once.
var fakeJWTHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// NewIssuerReadiness builds the readiness entry for an issuer: an HS256 JWT
// naming the issuer, signed with a key no issuer holds. It is assembled by
// hand because a throwaway token is all the probe needs, and a JOSE library
// for it alone would be one more dependency in the proxy binary.
func NewIssuerReadiness(issuerURL string) (IssuerReadiness, error) {
	claims, err := json.Marshal(struct {
		Subject   string `json:"sub"`
		Issuer    string `json:"iss"`
		NotBefore int64  `json:"nbf"`
	}{
		Subject:   "fake",
		Issuer:    issuerURL,
		NotBefore: time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	})
	if err != nil {
		return IssuerReadiness{}, fmt.Errorf("probe: encoding the token claims: %w", err)
	}

	signingInput := fakeJWTHeader + "." + base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, fakeJWTKey)
	mac.Write([]byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return IssuerReadiness{IssuerURL: issuerURL, FakeJWT: token}, nil
}

// Server is the readiness probe: it tracks per-issuer OIDC initialization,
// answers the liveness and readiness endpoints, and owns the listener they are
// served on. It gives that listener an explicit lifecycle: a caller Starts it
// (binding synchronously), the server serves until the supplied context is
// cancelled, and Wait reports the terminal serve error.
//
// It is safe for concurrent use: its issuer state is guarded by mu. serving is
// deliberately atomic rather than guarded by mu: check releases mu before the
// potentially slow AuthenticateToken calls (#53), and the serving flag must
// stay readable without re-entangling it with that lock.
type Server struct {
	// readinessLogger and oidcLogger are the two component loggers the probe
	// reports through: readiness for the ready latch and the probe listener,
	// oidc for the per-issuer records. Both are derived from the root logger
	// passed to NewServer, because a single component logger cannot carry two
	// components and the record registry fixes one per event.
	readinessLogger *slog.Logger
	oidcLogger      *slog.Logger

	// metrics receives the per-issuer and readiness gauges; nil records nothing.
	metrics *metrics.Recorder

	oidcAuthenticator authenticator.Token
	issuers           []IssuerReadiness
	requireAll        bool

	serving atomic.Bool

	mu          sync.Mutex
	ready       bool
	initialized map[string]bool

	// lastPending is the pending issuer set as of the previous check, joined
	// into a comparable key. The pending line is a state-change report, not a
	// per-probe status: the kubelet calls check every few seconds, so restating
	// an unchanged set would flood the log for as long as an issuer stays
	// unreachable.
	lastPending string

	srv *http.Server

	// shutdownTimeout bounds the graceful shutdown of this server. It is a
	// field rather than the package constant so a test can exercise the
	// shutdown failure path without waiting out the production budget.
	shutdownTimeout time.Duration

	// listener is the bound server once Start has succeeded.
	listener *httpserve.Serving
}

// Config is what the readiness probe needs from the command.
type Config struct {
	// Addr is the host:port the readiness listener binds, in the same form
	// the metrics listener takes.
	Addr string

	// Issuers are the issuers readiness waits for, each with the fake JWT
	// used to probe whether its authenticator has fetched its JWKS.
	Issuers []IssuerReadiness

	// RequireAllIssuers makes readiness wait for every issuer rather than
	// any one.
	RequireAllIssuers bool

	// Authenticator is the OIDC token authenticator the issuers are probed
	// through.
	Authenticator authenticator.Token

	// Metrics receives the issuer and readiness gauges. Optional: nil records
	// nothing.
	Metrics *metrics.Recorder
}

// NewServer builds a readiness Server for cfg. It does not bind or serve until
// Start is called. With a recorder, it seeds the readiness gauge and one
// issuer series per configured issuer at 0, so an issuer that never
// initializes is visible rather than absent.
//
// root must be the process root logger, not a component-bound one: unlike its
// sibling constructors, the probe reports under two components (readiness for
// the latch, oidc for the per-issuer records) and derives both itself. It is
// required, as it is for the proxy's other constructors; a test passes a
// discarding logger.
func NewServer(cfg Config, root *slog.Logger) (*Server, error) {
	if root == nil {
		return nil, errors.New("probe: logger is required")
	}

	s := &Server{
		readinessLogger:   logging.ForComponent(root, logging.ComponentReadiness),
		oidcLogger:        logging.ForComponent(root, logging.ComponentOIDC),
		oidcAuthenticator: cfg.Authenticator,
		issuers:           cfg.Issuers,
		requireAll:        cfg.RequireAllIssuers,
		initialized:       make(map[string]bool),
		metrics:           cfg.Metrics,
		shutdownTimeout:   shutdownTimeout,
	}
	s.srv = httpserve.NewServer(cfg.Addr, s.handler())

	cfg.Metrics.SetReady(false)
	for _, issuer := range cfg.Issuers {
		cfg.Metrics.SetIssuerInitialized(authn.IssuerName(issuer.IssuerURL), false)
	}
	return s, nil
}

// SetServing records that the proxy has started serving. Until it is called,
// readiness reports not-ready regardless of issuer state; after it, readiness
// depends solely on issuer initialization.
func (s *Server) SetServing() {
	s.serving.Store(true)
}

// handler builds the readiness listener's HTTP handler. It exposes a liveness
// endpoint that is always healthy once this probe listener is up — it is
// deliberately not gated on SetServing, since the process is alive long before
// the proxy serves and gating it would invite restarts during startup — and a
// readiness endpoint driven by check. Both endpoints only answer GET (returning 405
// otherwise, matching the previous healthcheck handler); unknown paths yield
// 404 via the ServeMux default.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/live", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/ready", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if err := s.check(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	return mux
}

// getOnly rejects any non-GET request with 405 before invoking next, preserving
// the GET-only contract of the readiness/liveness endpoints.
func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

// Start binds the readiness listener synchronously so a failure to acquire the
// port is surfaced to the caller at startup rather than being swallowed inside
// a goroutine. On success it serves in the background and gracefully shuts the
// server down (bounded by shutdownTimeout) once ctx is cancelled. Start returns
// once the listener is bound; use Wait to block on the terminal serve error.
//
// Start reports readiness.server.started itself, with the bound address: each
// listener's Start owns its own started record, as metrics.Server.Start does,
// because only it knows the bind succeeded and where.
func (s *Server) Start(ctx context.Context) error {
	listener, err := httpserve.Start(ctx, s.srv, s.shutdownTimeout, func(err error) {
		// Called once ctx is already cancelled, so the record gets a context
		// of its own; it carries no deadline and no request scope anyway.
		logging.Emit(context.Background(), s.readinessLogger, logging.EventReadinessServerFailed, logging.ErrAttr(err))
	})
	if err != nil {
		return fmt.Errorf("probe: listening on %s: %w", s.srv.Addr, err)
	}
	s.listener = listener

	logging.Emit(ctx, s.readinessLogger, logging.EventReadinessServerStarted, slog.String("address", s.Addr()))
	return nil
}

// Addr returns the address the listener is bound to, which differs from the
// configured one when the port was 0. Empty before Start.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr()
}

// Wait blocks until serving and the graceful shutdown have both finished and
// returns the terminal error: a listener failure, a drain that overran its
// budget, or nil after a clean stop. http.ErrServerClosed is normalized to
// nil. It may be called by multiple goroutines.
func (s *Server) Wait() error {
	if s.listener == nil {
		return nil
	}
	return s.listener.Wait()
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
	toProbe := make([]IssuerReadiness, 0, len(s.issuers))
	for _, issuer := range s.issuers {
		if !s.initialized[issuer.IssuerURL] {
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
		if _, _, err := s.oidcAuthenticator.AuthenticateToken(ctx, issuer.FakeJWT); err != nil {
			if reason, isPending := classifyPending(err); isPending {
				pending = append(pending, pendingIssuer{issuerURL: issuer.IssuerURL, reason: reason})
				continue
			}
		}
		newlyInitialized = append(newlyInitialized, issuer.IssuerURL)
	}

	// Re-acquire the lock to record results and evaluate readiness.
	s.mu.Lock()
	defer s.mu.Unlock()

	pending = s.recordProbeResults(ctx, newlyInitialized, pending)

	if s.ready {
		return nil
	}

	if s.requireAll && len(pending) > 0 {
		return errors.New("OIDC providers not yet initialized")
	}
	if !s.requireAll && len(s.initialized) == 0 {
		return errors.New("no OIDC provider initialized yet")
	}

	s.ready = true
	s.metrics.SetReady(true)
	logging.Emit(ctx, s.readinessLogger, logging.EventReadinessProxyReady,
		slog.Int("ready_issuers", len(s.initialized)),
		slog.Int("total_issuers", len(s.issuers)),
		slog.String("readiness_mode", string(ReadinessModeFor(s.requireAll))))
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
