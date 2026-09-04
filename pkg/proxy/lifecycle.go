// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

// How a request ended, as reported by the terminal record's termination. The
// first four are decided by the lifecycle filter itself; the upstream three are
// classified by the error handler and handed over on the request's termination
// holder.
const (
	terminationNormal       = "normal"
	terminationHijacked     = "hijacked"
	terminationClientCancel = "client_cancel"
	terminationPanic        = "panic"

	terminationUpstreamTimeout = "upstream_timeout"
	terminationUpstreamReset   = "upstream_reset"
	terminationProxyError      = "proxy_error"
)

// responseRecorder wraps the ResponseWriter for the length of one request so
// the terminal record can report what was actually sent: the status the
// handler chose, the bytes it wrote, and whether it took the connection over.
//
// It deliberately implements only what the proxy's own chain and the reverse
// proxy need — Flusher for streaming responses and Hijacker for the SPDY
// upgrades exec, attach and portforward perform — plus Unwrap, so anything
// downstream that probes for a richer ResponseWriter can still reach the real
// one instead of silently losing the interface.
type responseRecorder struct {
	http.ResponseWriter

	status   int
	bytes    int64
	wrote    bool
	hijacked bool

	// onStart, when set, reports the first WriteHeader. Only long-running
	// requests set it: for everything else the terminal record arrives close
	// enough behind the headers that a second record says nothing new.
	onStart func(status int)
}

// WriteHeader records the status the handler chose. Only the first call counts,
// as net/http itself does: a duplicate is ignored rather than overwriting the
// status that actually went on the wire.
func (r *responseRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
	if r.onStart != nil {
		r.onStart(code)
	}
}

// Write counts what the handler sent, supplying the implicit 200 net/http
// would write for a handler that never called WriteHeader.
func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Flush records the implicit 200 that net/http sends when a handler flushes
// before it has written anything, and only then forwards the call. Forwarded
// untouched, the status would be written by the ResponseWriter underneath and
// this recorder would never learn a response had begun: a watch that flushes
// its headers and then streams for an hour would produce no started record and
// a terminal record claiming http_status=0.
//
// Nothing is synthesised when there is no Flusher underneath, because then no
// flush -- and so no implicit status -- happens either.
func (r *responseRecorder) Flush() {
	f, ok := r.ResponseWriter.(http.Flusher)
	if !ok {
		return
	}
	if !r.wrote {
		r.WriteHeader(http.StatusOK)
	}
	f.Flush()
}

// Hijack hands the connection to the caller and marks the response as no longer
// this recorder's to describe: once the handler owns the socket, neither the
// status nor the byte count means anything.
func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := h.Hijack()
	if err == nil {
		r.hijacked = true
	}
	return c, rw, err
}

// Unwrap returns the wrapped ResponseWriter, the convention net/http uses to
// see through a wrapper.
func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// isAbortHandler reports whether a recovered value is the http.ErrAbortHandler
// sentinel, which a handler panics with to abandon a response deliberately.
// httputil.ReverseProxy uses it for a copy error mid-stream, so it marks the
// end of a request rather than a bug in one.
func isAbortHandler(panicked any) bool {
	err, ok := panicked.(error)
	return ok && errors.Is(err, http.ErrAbortHandler)
}

// withRequestLifecycle writes the terminal record for every request: what the
// client was answered, how long it took, and how the exchange ended. It runs
// directly inside withRequestID so the record exists whatever the rest of the
// chain does — including a handler that panics, which is recorded and then
// re-panicked for the server's own recovery to deal with.
//
// A long-running request also gets a record when its headers go out, mirroring
// the audit stage ResponseStarted: a watch or an exec that streams for hours
// would otherwise be invisible until it ended.
func (p *Proxy) withRequestLifecycle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		req = context.WithTerminationHolder(req)
		req = context.WithDecisionHolder(req)
		ctx := req.Context()
		l := logging.FromContext(ctx)

		rec := &responseRecorder{ResponseWriter: w}
		if audit.IsLongRunning(req) {
			rec.onStart = func(code int) {
				logging.Emit(ctx, l, logging.EventRequestResponseStarted,
					slog.Int("http_status", code),
					slog.Int64("time_to_headers_ms", time.Since(start).Milliseconds()))
			}
		}

		defer func() {
			panicked := recover()
			classified := context.TerminationFrom(req)

			term := terminationNormal
			switch {
			// An http.ErrAbortHandler panic is not a fault: it is how
			// httputil.ReverseProxy reports a response copy that failed after
			// the headers went out. Whether the client went away or the
			// upstream connection broke is then decided exactly as it is for a
			// request that never panicked, so the two cases below classify it.
			case panicked != nil && !isAbortHandler(panicked):
				term = terminationPanic
			case rec.hijacked:
				term = terminationHijacked
			case ctx.Err() != nil:
				term = terminationClientCancel
			case panicked != nil:
				// Aborted with the client still attached: the stream broke on
				// the upstream side.
				term = terminationUpstreamReset
			case classified.Termination != "":
				// Set by the error handler for an upstream failure.
				term = classified.Termination
			}

			attrs := []slog.Attr{
				slog.Int("http_status", rec.status),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
				slog.String("termination", term),
			}
			// A hijacked connection is no longer described by the recorder: the
			// handler wrote to the socket directly, so a byte count of zero
			// would be a claim rather than a measurement.
			if !rec.hijacked {
				attrs = append(attrs, slog.Int64("response_bytes", rec.bytes))
			}
			// The classified reason travels with its termination, so a query on
			// the terminal record alone can tell an upstream failure from an
			// ordinary completion.
			if term == classified.Termination && classified.Reason != "" {
				attrs = append(attrs, slog.String("reason", classified.Reason))
			}

			logging.Emit(ctx, l, logging.EventRequestResponseCompleted, attrs...)

			if panicked != nil {
				panic(panicked)
			}
		}()

		next.ServeHTTP(rec, req)
	})
}
