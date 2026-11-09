// Copyright Jetstack Ltd. See LICENSE for details.

// Package httpserve gives an http.Server the explicit lifecycle the proxy's
// auxiliary listeners share: bind synchronously so a port-in-use failure
// surfaces at startup, serve in the background until a context is cancelled,
// shut down gracefully inside a budget, and report one terminal error through
// Wait. The readiness probe and the metrics endpoint both serve this way;
// keeping the mechanics here means they cannot drift apart.
package httpserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// WriteTimeout bounds how long a listener may take to write a response. A
// handler with a deadline of its own (the metrics scrape, the readiness
// check) must finish well inside it, or the error it writes on timing out
// never reaches the client.
const WriteTimeout = 30 * time.Second

// The remaining limits of the shared listener hardening. ReadHeaderTimeout is
// the Slowloris guard (gosec G112): both endpoints are reachable by anything
// that can dial the pod, so an unbounded header read lets idle connections
// accumulate. MaxHeaderBytes leaves room for a bearer token and little else;
// neither endpoint reads a request body.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 << 10
)

// NewServer returns an http.Server for addr and h carrying the listener limits
// the auxiliary listeners share, so the readiness and metrics ports cannot be
// hardened differently.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      WriteTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

// Serving is a bound http.Server that is serving or has finished. It is
// created by Start and read through Addr and Wait.
type Serving struct {
	srv             *http.Server
	listener        net.Listener
	shutdownTimeout time.Duration

	// done is closed once serving and shutdown have both finished; err holds
	// the terminal error (nil after a clean shutdown). Closing done
	// happens-after the write to err, so Wait reads it without further
	// synchronisation.
	done chan struct{}
	err  error
}

// Start binds srv.Addr synchronously and returns the listen error as is, so
// the caller can name the listener in its own words. On success it serves in
// the background until ctx is cancelled. Cancellation starts a graceful
// shutdown bounded by shutdownTimeout; a request that does not finish inside
// it is closed and the timeout is reported through Wait. onFailed, when not
// nil, is called with the terminal error before Wait returns it, so the owner
// can emit its own record.
func Start(ctx context.Context, srv *http.Server, shutdownTimeout time.Duration, onFailed func(error)) (*Serving, error) {
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return nil, err
	}

	s := &Serving{
		srv:             srv,
		listener:        ln,
		shutdownTimeout: shutdownTimeout,
		done:            make(chan struct{}),
	}

	// Serve's result travels on a channel so the single owner goroutine
	// below can join it whichever way serving ended.
	serveResult := make(chan error, 1)
	go func() { serveResult <- srv.Serve(ln) }()

	// One goroutine owns shutdown and the terminal error. Shutdown makes
	// Serve return at once, so closing done when Serve returns would report
	// the listener as stopped while it is still draining -- and would drop
	// the drain's error, which the process joins into its exit status. done
	// is closed here instead, once both have finished.
	//
	//nolint:gosec // G118: this goroutine runs because ctx was cancelled; a context derived from it would be dead on arrival and Shutdown would not drain the in-flight request.
	go func() {
		defer close(s.done)

		var serveErr, shutdownErr error
		select {
		case serveErr = <-serveResult:
			// Serving stopped on its own (a listener error, or a direct
			// Shutdown call): nothing is draining, but any open connection is
			// closed for hygiene.
			shutdownErr = srv.Close()
		case <-ctx.Done():
			shutdownErr = s.Shutdown()
			if shutdownErr != nil {
				shutdownErr = errors.Join(shutdownErr, srv.Close())
			}
			serveErr = <-serveResult
		}
		// A graceful shutdown is expected, not a failure.
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
		s.err = errors.Join(serveErr, shutdownErr)
		if s.err != nil && onFailed != nil {
			onFailed(s.err)
		}
	}()

	return s, nil
}

// Addr returns the address the listener is bound to, which differs from the
// configured one when the port was 0.
func (s *Serving) Addr() string {
	return s.listener.Addr().String()
}

// Shutdown gracefully stops the server inside the shutdown budget. It is safe
// to call more than once, and it is what cancelling the Start context does.
func (s *Serving) Shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), s.shutdownTimeout)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// CloseListener closes the listener out from under Serve, which makes serving
// fail rather than stop gracefully. It exists so a test can drive the failure
// path without a real network fault.
func (s *Serving) CloseListener() error {
	return s.listener.Close()
}

// Wait blocks until serving and shutdown have both finished and returns the
// terminal error: a listener failure, a shutdown that overran its budget, or
// nil after a clean stop. It may be called by multiple goroutines.
func (s *Serving) Wait() error {
	<-s.done
	return s.err
}
