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
func NewServer(port string, issuers []IssuerReadiness, requireAll bool, oidcAuther authenticator.Token) *Server {
	h := &HealthCheck{
		handler:     healthcheck.NewHandler(),
		oidcAuther:  oidcAuther,
		issuers:     issuers,
		requireAll:  requireAll,
		initialized: make(map[string]bool),
	}

	h.handler.AddReadinessCheck("secure serving", h.Check)

	return &Server{
		hc: h,
		srv: &http.Server{
			Addr:    net.JoinHostPort("0.0.0.0", port),
			Handler: h.handler,
		},
		served: make(chan struct{}),
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
				klog.Errorf("readiness probe shutdown error: %s", err)
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

// Check probes every issuer that has not yet been observed as initialized,
// logs per-issuer transitions and any still-pending issuers, and reports
// readiness. Once readiness latches (via ready.Store(true)) it always
// returns nil, but probing and pending-issuer logging continue on every
// call so operators keep seeing progress for issuers that initialize late.
func (h *HealthCheck) Check() error {
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
	var newlyInitialized, pending []string
	for _, issuer := range toProbe {
		_, _, err := h.oidcAuther.AuthenticateToken(ctx, issuer.FakeJWT)
		// The issuer counts as initialized only once its authenticator reaches
		// token verification. A "not initialized" signal (JWKS not fetched yet)
		// or a transient network/timeout error both leave it pending; check
		// "not initialized" first since it is the more specific signal.
		if err != nil && (isNotInitialized(err) || isTransient(err)) {
			pending = append(pending, issuer.IssuerURL)
			continue
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
		klog.Infof("OIDC issuer initialized: %s (%d/%d ready)", issuerURL, len(h.initialized), len(h.issuers))
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
