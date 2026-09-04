// Copyright Jetstack Ltd. See LICENSE for details.

// Package probe implements the proxy's readiness and liveness HTTP endpoints,
// reporting readiness once the proxy is serving and the configured OIDC
// issuers' authenticators have completed initialization.
package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apiserver/pkg/authentication/authenticator"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

const (
	// readHeaderTimeout bounds how long a client may take to send request
	// headers to the readiness listener.
	readHeaderTimeout = 5 * time.Second

	timeout = time.Second * 10

	// shutdownTimeout bounds the graceful shutdown of the readiness server so a
	// stuck connection cannot block process teardown indefinitely.
	shutdownTimeout = time.Second * 5
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

// Pending reasons classify why an issuer is not yet initialized. They are the
// closed pending_reason value set carried by the oidc.issuer.pending record.
const (
	pendingNotInitialized = "not_initialized"
	pendingTransient      = "transient"
	pendingError          = "error"
)

// IssuerName derives the name an issuer is known by in the log stream. The full
// issuer URL is never logged, so the host identifies the issuer; a value that
// does not parse, or carries no host, falls back to the bounded raw string, and
// an empty one to a placeholder, so the field is never empty.
func IssuerName(issuerURL string) string {
	if u, err := url.Parse(issuerURL); err == nil && u.Host != "" {
		return logging.Bound(u.Host, logging.MaxIdentity)
	}
	if name := logging.Bound(issuerURL, logging.MaxIdentity); strings.TrimSpace(name) != "" {
		return name
	}
	return "unknown"
}

// pendingIssuer is one issuer that failed its probe, with the classification
// of why. The reason is part of the state the pending record reports on
// change: an issuer that moves from unreachable to still-initializing is a
// change an operator wants to see.
type pendingIssuer struct {
	issuerURL string
	reason    string
}

// IssuerReadiness pairs an issuer with the fake JWT used to probe whether
// its authenticator has completed JWKS initialization.
type IssuerReadiness struct {
	IssuerURL string
	FakeJWT   string
}

// HealthCheck tracks per-issuer OIDC initialization and answers readiness
// checks. It is safe for concurrent use: its issuer state is guarded by mu.
//
// serving is deliberately atomic rather than guarded by mu: Check releases mu
// before the potentially slow AuthenticateToken calls (#53), and the serving
// flag must stay readable without re-entangling it with that lock.
type HealthCheck struct {
	// readinessLogger and oidcLogger are the two component loggers this check
	// reports through: readiness for the ready latch and the probe listener,
	// oidc for the per-issuer records. Both are derived from the root logger
	// passed to NewServer, because a single component logger cannot carry two
	// components and the record registry fixes one per event.
	readinessLogger *slog.Logger
	oidcLogger      *slog.Logger

	oidcAuther authenticator.Token
	issuers    []IssuerReadiness
	requireAll bool

	serving atomic.Bool

	mu          sync.Mutex
	ready       bool
	initialized map[string]bool

	// lastPending is the pending issuer set as of the previous Check, joined
	// into a comparable key. The pending line is a state-change report, not a
	// per-probe status: the kubelet calls Check every few seconds, so restating
	// an unchanged set would flood the log for as long as an issuer stays
	// unreachable.
	lastPending string
}

// SetServing records that the proxy has started serving. Until it is called,
// Check reports not-ready regardless of issuer state.
func (h *HealthCheck) SetServing() {
	h.serving.Store(true)
}

// Server owns the readiness HTTP listener and gives it an explicit lifecycle:
// a caller Starts it (binding synchronously), the server serves until the
// supplied context is cancelled, and Wait reports the terminal serve error.
type Server struct {
	hc  *HealthCheck
	srv *http.Server

	// served is closed once Serve returns; err holds the terminal serve error
	// (nil after a clean shutdown). Closing served happens-after the write to
	// err, so Wait observes err safely without additional synchronization.
	served chan struct{}
	err    error
}

// NewServer builds a readiness Server that probes the given issuers via
// oidcAuther and serves the readiness endpoint on the given port. It does not
// bind or serve until Start is called.
//
// logger is the root logger: the probe reports under two components (readiness
// for the latch, oidc for the per-issuer records) and derives both from it. A
// nil logger yields one that discards every record, so a partially wired caller
// cannot panic on a probe.
func NewServer(port string, issuers []IssuerReadiness, requireAll bool, oidcAuther authenticator.Token, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}

	h := &HealthCheck{
		readinessLogger: logging.ForComponent(logger, logging.ComponentReadiness),
		oidcLogger:      logging.ForComponent(logger, logging.ComponentOIDC),
		oidcAuther:      oidcAuther,
		issuers:         issuers,
		requireAll:      requireAll,
		initialized:     make(map[string]bool),
	}

	return &Server{
		hc: h,
		srv: &http.Server{
			Addr:    net.JoinHostPort("0.0.0.0", port),
			Handler: h.handler(),

			// Bound how long a client may take to send its headers. The
			// readiness endpoint is reachable by anything that can dial the
			// probe port, so an unbounded header read lets idle connections
			// accumulate (gosec G112, Slowloris).
			ReadHeaderTimeout: readHeaderTimeout,
		},
		served: make(chan struct{}),
	}
}

// SetServing records that the proxy has started serving, so readiness may now
// depend solely on issuer initialization. It is a pass-through to the
// underlying HealthCheck, which keeps that type out of the caller's surface.
func (s *Server) SetServing() {
	s.hc.SetServing()
}

// handler builds the readiness listener's HTTP handler. It exposes a liveness
// endpoint that is always healthy once this probe listener is up — it is
// deliberately not gated on SetServing, since the process is alive long before
// the proxy serves and gating it would invite restarts during startup — and a
// readiness endpoint driven by Check. Both endpoints only answer GET (returning 405
// otherwise, matching the previous healthcheck handler); unknown paths yield
// 404 via the ServeMux default.
func (h *HealthCheck) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/live", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	mux.HandleFunc("/ready", getOnly(func(w http.ResponseWriter, _ *http.Request) {
		if err := h.Check(); err != nil {
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
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("readiness probe failed to listen on %s: %w", s.srv.Addr, err)
	}

	go func() {
		serveErr := s.srv.Serve(ln)
		// A graceful shutdown is expected, not a failure.
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		s.err = serveErr
		close(s.served)
	}()

	// Bridge context cancellation to a bounded graceful shutdown. This goroutine
	// exits either when ctx is cancelled or when serving has already stopped, so
	// it never outlives the server (no leak across repeated Start/Shutdown).
	go func() {
		select {
		case <-ctx.Done():
			if err := s.Shutdown(); err != nil {
				// ctx is already cancelled here, which the record does not care
				// about: it carries no deadline and no request scope.
				logging.Emit(ctx, s.hc.readinessLogger,
					logging.EventReadinessServerFailed, logging.ErrAttr(err))
			}
		case <-s.served:
		}
	}()

	return nil
}

// Shutdown gracefully stops the readiness server with a bounded timeout. It is
// safe to call more than once and is invoked automatically when the context
// passed to Start is cancelled.
func (s *Server) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// Wait blocks until the server has stopped serving and returns the terminal
// serve error, with http.ErrServerClosed normalized to nil. It may be called
// by multiple goroutines.
func (s *Server) Wait() error {
	<-s.served
	return s.err
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

// pendingReason classifies the error from an issuer probe into the closed
// pending_reason value set. "not_initialized" is the authenticator saying its
// JWKS is not fetched yet and "transient" a network or timeout failure; both
// leave the issuer pending. "error" is anything else — an error raised at token
// verification, which means the JWKS did load, so the issuer counts as
// initialized and never reaches a pending record. It is kept as the explicit
// default rather than an implicit one so the classification has no silent case.
func (h *HealthCheck) pendingReason(err error) string {
	switch {
	case isNotInitialized(err):
		return pendingNotInitialized
	case isTransient(err):
		return pendingTransient
	default:
		return pendingError
	}
}

// Check reports readiness. It first requires the proxy to be serving, then
// probes every issuer that has not yet been observed as initialized, logging
// per-issuer transitions and any still-pending issuers. Once readiness latches
// (h.ready is set true under h.mu) it always returns nil, but probing and
// pending-issuer logging continue on every call so operators keep seeing
// progress for issuers that initialize late.
func (h *HealthCheck) Check() error {
	// Checked first: it is cheap, and it is the more fundamental condition. An
	// initialized issuer on a process that is not yet answering requests is not
	// readiness — advertising it would put the pod into its Service while
	// requests could only queue.
	if !h.serving.Load() {
		return errors.New("proxy is not yet serving")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Snapshot the issuers still needing a probe under the lock, then release it
	// so the potentially slow AuthenticateToken calls run lock-free. No blocking
	// authenticator call may run while h.mu is held (#53).
	h.mu.Lock()
	toProbe := make([]IssuerReadiness, 0, len(h.issuers))
	for _, issuer := range h.issuers {
		if !h.initialized[issuer.IssuerURL] {
			toProbe = append(toProbe, issuer)
		}
	}
	h.mu.Unlock()

	// Probe each not-yet-initialized issuer without holding the lock.
	var newlyInitialized []string
	var pending []pendingIssuer
	for _, issuer := range toProbe {
		_, _, err := h.oidcAuther.AuthenticateToken(ctx, issuer.FakeJWT)
		// The issuer counts as initialized only once its authenticator reaches
		// token verification. A "not initialized" signal (JWKS not fetched yet)
		// or a transient network/timeout error both leave it pending; anything
		// else was raised at verification, so the JWKS did load.
		if err != nil {
			if reason := h.pendingReason(err); reason != pendingError {
				pending = append(pending, pendingIssuer{issuerURL: issuer.IssuerURL, reason: reason})
				continue
			}
		}
		newlyInitialized = append(newlyInitialized, issuer.IssuerURL)
	}

	// Re-acquire the lock to record results and evaluate readiness.
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, issuerURL := range newlyInitialized {
		if h.initialized[issuerURL] {
			continue
		}
		h.initialized[issuerURL] = true
		logging.Emit(ctx, h.oidcLogger, logging.EventOIDCIssuerInitialized,
			slog.String("issuer_name", IssuerName(issuerURL)),
			slog.String("issuer_state", "initialized"),
			slog.Int("ready_issuers", len(h.initialized)),
			slog.Int("total_issuers", len(h.issuers)))
	}

	// Report only on change, and record the new state either way so that a
	// pending set which clears and later recurs is reported again. The reason
	// is part of the state: an issuer moving from unreachable to still
	// initializing is a change worth a record.
	if key := pendingKey(pending); key != h.lastPending {
		for _, p := range pending {
			logging.Emit(ctx, h.oidcLogger, logging.EventOIDCIssuerPending,
				slog.String("issuer_name", IssuerName(p.issuerURL)),
				slog.String("issuer_state", "pending"),
				slog.String("pending_reason", p.reason),
				slog.Int("ready_issuers", len(h.initialized)),
				slog.Int("total_issuers", len(h.issuers)))
		}
		h.lastPending = key
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
	logging.Emit(ctx, h.readinessLogger, logging.EventReadinessProxyReady,
		slog.Int("ready_issuers", len(h.initialized)),
		slog.Int("total_issuers", len(h.issuers)),
		slog.String("readiness_mode", ReadinessMode(h.requireAll)))
	return nil
}

// pendingKey renders the pending set as a comparable string so an unchanged
// set is not restated on every kubelet probe. The probe order follows the
// configured issuer order, so no sort is needed.
func pendingKey(pending []pendingIssuer) string {
	parts := make([]string, len(pending))
	for i, p := range pending {
		parts[i] = p.issuerURL + "=" + p.reason
	}
	return strings.Join(parts, ",")
}

// ReadinessMode renders --readiness-require-all-issuers as the closed
// readiness_mode value carried by the startup and readiness records. It lives
// here because the probe is what the flag configures.
func ReadinessMode(requireAll bool) string {
	if requireAll {
		return "all"
	}
	return "any"
}
