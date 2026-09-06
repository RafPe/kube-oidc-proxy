// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
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
	srv      *http.Server
	logger   *slog.Logger
	listener net.Listener

	shutdownTimeout time.Duration

	// done is closed once serving and shutdown have both finished; err holds
	// the terminal error (nil after a clean shutdown). Closing done
	// happens-after the write to err, so Wait reads it without further
	// synchronisation.
	done chan struct{}
	err  error
}

// NewServer builds a Server exposing rec on addr. It does not bind until
// Start. A nil logger discards every record.
func NewServer(addr string, rec *Recorder, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{
		logger:          logger,
		shutdownTimeout: shutdownTimeout,
		srv: &http.Server{
			Addr:              addr,
			Handler:           rec.Handler(logger),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			MaxHeaderBytes:    maxHeaderBytes,
		},
		done: make(chan struct{}),
	}
}

// Addr returns the address the listener is bound to, which differs from the
// configured one when the port was 0. Empty before Start.
func (s *Server) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Start binds the listener synchronously so a port-in-use failure surfaces at
// startup, then serves in the background until ctx is cancelled. Cancellation
// starts a graceful shutdown bounded by shutdownTimeout; a scrape that does not
// finish inside it is closed and the timeout is reported through Wait.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return fmt.Errorf("metrics listener failed to listen on %s: %w", s.srv.Addr, err)
	}
	s.listener = ln

	// Serve's result travels on a channel so the single owner goroutine
	// below can join it whichever way serving ended.
	serveResult := make(chan error, 1)
	go func() { serveResult <- s.srv.Serve(ln) }()

	// One goroutine owns shutdown and the terminal error. Shutdown makes
	// Serve return at once; net/http requires waiting for Shutdown itself,
	// which is why done is closed here and not when Serve returns.
	//
	//nolint:gosec // G118: this goroutine runs because ctx was cancelled; a context derived from it would be dead on arrival and Shutdown would not drain in-flight scrapes (TestServerWaitDrainsAnActiveScrape pins this).
	go func() {
		defer close(s.done)

		var serveErr, shutdownErr error
		select {
		case serveErr = <-serveResult:
			// Serving stopped on its own (listener error): nothing is
			// draining, but any open connection is closed for hygiene.
			shutdownErr = s.srv.Close()
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
			shutdownErr = s.srv.Shutdown(shutdownCtx)
			cancel()
			if shutdownErr != nil {
				shutdownErr = errors.Join(shutdownErr, s.srv.Close())
			}
			serveErr = <-serveResult
		}
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		s.err = errors.Join(serveErr, shutdownErr)
		if s.err != nil {
			logging.Emit(context.Background(), s.logger, logging.EventMetricsServerFailed, logging.ErrAttr(s.err))
		}
	}()

	logging.Emit(ctx, s.logger, logging.EventMetricsServerStarted, slog.String("address", s.Addr()))
	return nil
}

// Wait blocks until serving and shutdown have both finished and returns the
// terminal error: a listener failure, a shutdown that overran its budget, or
// nil after a clean stop.
func (s *Server) Wait() error {
	<-s.done
	return s.err
}
