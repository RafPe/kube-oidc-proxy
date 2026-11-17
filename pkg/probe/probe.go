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
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
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

// issuerReadiness pairs an issuer with the fake JWT used to probe whether
// its authenticator has completed JWKS initialization.
type issuerReadiness struct {
	issuerURL string
	fakeJWT   string
}

// fakeJWTKey signs the probe token. The token is meant to fail verification:
// what the probe reads is how the authenticator refuses it, which tells an
// issuer still fetching its keys from one that has them. Nothing trusts this
// key, so it need not be secret.
var fakeJWTKey = []byte("this-is-a-32-byte-long-secret-key!!!!")

// fakeJWTHeader is the probe token's JOSE header, base64url-encoded once.
var fakeJWTHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// newIssuerReadiness builds the readiness entry for an issuer: an HS256 JWT
// naming the issuer, signed with a key no issuer holds. It is assembled by
// hand because a throwaway token is all the probe needs, and a JOSE library
// for it alone would be one more dependency in the proxy binary.
func newIssuerReadiness(issuerURL string) issuerReadiness {
	// Marshalling two strings and an integer cannot fail, so the error is
	// not a path this function has.
	claims, _ := json.Marshal(struct {
		Subject   string `json:"sub"`
		Issuer    string `json:"iss"`
		NotBefore int64  `json:"nbf"`
	}{
		Subject:   "fake",
		Issuer:    issuerURL,
		NotBefore: time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
	})

	signingInput := fakeJWTHeader + "." + base64.RawURLEncoding.EncodeToString(claims)
	mac := hmac.New(sha256.New, fakeJWTKey)
	mac.Write([]byte(signingInput))
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return issuerReadiness{issuerURL: issuerURL, fakeJWT: token}
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

	// metrics receives the per-issuer and readiness gauges.
	metrics *metrics.Recorder

	oidcAuthenticator authenticator.Token
	issuers           []issuerReadiness
	mode              ReadinessMode

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

	// IssuerURLs are the issuers readiness waits for. The probe builds the
	// fake JWT it sends each one to learn whether its authenticator has
	// fetched its JWKS.
	IssuerURLs []string

	// Mode is whether readiness waits for any one issuer or for all of them.
	// The zero value is ReadinessAny.
	Mode ReadinessMode

	// Authenticator is the OIDC token authenticator the issuers are probed
	// through.
	Authenticator authenticator.Token

	// Metrics receives the issuer and readiness gauges. Optional; see package
	// metrics.
	Metrics *metrics.Recorder
}

// NewServer builds a readiness Server for cfg. It does not bind or serve until
// Start is called. With a recorder, it seeds the readiness gauge and one
// issuer series per configured issuer at 0, so an issuer that never
// initializes is visible rather than absent.
//
// root is the process root logger, from which NewServer derives the readiness
// component logger for the latch and the listener and the oidc one for the
// per-issuer records.
func NewServer(cfg Config, root *slog.Logger) *Server {
	logging.RequireLogger(root, "probe")

	mode := cfg.Mode
	if mode == "" {
		mode = ReadinessAny
	}
	issuers := make([]issuerReadiness, 0, len(cfg.IssuerURLs))
	for _, issuerURL := range cfg.IssuerURLs {
		issuers = append(issuers, newIssuerReadiness(issuerURL))
	}

	s := &Server{
		readinessLogger:   logging.ForComponent(root, logging.ComponentReadiness),
		oidcLogger:        logging.ForComponent(root, logging.ComponentOIDC),
		oidcAuthenticator: cfg.Authenticator,
		issuers:           issuers,
		mode:              mode,
		initialized:       make(map[string]bool),
		metrics:           cfg.Metrics,
		shutdownTimeout:   shutdownTimeout,
	}
	s.srv = httpserve.NewHTTPServer(cfg.Addr, s.handler(), s.readinessLogger)

	cfg.Metrics.SetReady(false)
	for _, issuerURL := range cfg.IssuerURLs {
		cfg.Metrics.SetIssuerInitialized(authn.IssuerName(issuerURL), false)
	}
	return s
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
// readiness endpoint driven by check. Both are GET routes, as /metrics is on
// the metrics listener: ServeMux admits GET and HEAD, answers any other method
// with 405 and an Allow header, and an unknown path with 404.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /ready", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.check(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return mux
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
