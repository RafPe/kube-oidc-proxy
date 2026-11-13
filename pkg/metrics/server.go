// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/util/httpserve"
)

// Listener timeouts. ReadHeaderTimeout matches the probe listener (gosec
// G112, Slowloris). WriteTimeout must exceed scrapeTimeout or the 503 the
// handler writes on a slow gather never reaches the scraper. MaxHeaderBytes
// leaves room for a bearer token and nothing else.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 << 10

	shutdownTimeout = 5 * time.Second
)

// Server owns the metrics listener and gives it an explicit lifecycle: Start
// binds synchronously, the server serves until ctx is cancelled, and Wait
// blocks until the graceful shutdown has finished and reports its terminal
// error. Start is called once.
type Server struct {
	srv    *http.Server
	logger *slog.Logger

	// shutdownTimeout bounds the graceful shutdown. It is a field rather than
	// the package constant so a test can exercise the timeout path without
	// waiting out the production budget.
	shutdownTimeout time.Duration

	// serving is the bound server once Start has succeeded.
	serving *httpserve.Serving
}

// ServerConfig is what the metrics listener needs from the command.
type ServerConfig struct {
	// Addr is the host:port the listener binds.
	Addr string

	// Recorder is the registry the listener exposes.
	Recorder *Recorder
}

// NewServer builds a Server exposing cfg.Recorder on cfg.Addr. It does not
// bind until Start. logger is required; a test passes a discarding logger.
func NewServer(cfg ServerConfig, logger *slog.Logger) *Server {
	return &Server{
		logger:          logger,
		shutdownTimeout: shutdownTimeout,
		srv: &http.Server{
			Addr:              cfg.Addr,
			Handler:           cfg.Recorder.Handler(logger),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
		},
	}
}

// Addr returns the address the listener is bound to, which differs from the
// configured one when the port was 0. Empty before Start.
func (s *Server) Addr() string {
	if s.serving == nil {
		return ""
	}
	return s.serving.Addr()
}

// Start binds the listener synchronously so a port-in-use failure surfaces at
// startup, then serves in the background until ctx is cancelled. Cancellation
// starts a graceful shutdown bounded by shutdownTimeout; a scrape that does not
// finish inside it is closed and the timeout is reported through Wait.
func (s *Server) Start(ctx context.Context) error {
	serving, err := httpserve.Start(ctx, s.srv, s.shutdownTimeout, func(err error) {
		logging.Emit(context.Background(), s.logger, logging.EventMetricsServerFailed, logging.ErrAttr(err))
	})
	if err != nil {
		return fmt.Errorf("metrics listener failed to listen on %s: %w", s.srv.Addr, err)
	}
	s.serving = serving

	logging.Emit(ctx, s.logger, logging.EventMetricsServerStarted, slog.String("address", s.Addr()))
	return nil
}

// Wait blocks until serving and shutdown have both finished and returns the
// terminal error: a listener failure, a shutdown that overran its budget, or
// nil after a clean stop. Before a successful Start there is nothing to wait
// for, and it returns nil.
func (s *Server) Wait() error {
	if s.serving == nil {
		return nil
	}
	return s.serving.Wait()
}
