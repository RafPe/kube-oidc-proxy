// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
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

	// onStart, when set, reports the first final status; a forwarded 1xx does
	// not start the response. Only long-running requests set it: for everything
	// else the terminal record arrives close enough behind the headers that a
	// second record says nothing new.
	onStart func(status int)

	// onHijack, when set, reports a successful hijack. httputil.ReverseProxy
	// hijacks first and writes the 101 onto the connection itself, so the
	// recorder never sees a WriteHeader for an upgrade; this is how an exec or
	// attach still counts as an established stream.
	onHijack func()
}

// WriteHeader records the status the handler chose. Only the first final
// status counts, as net/http itself does: a duplicate is ignored rather than
// overwriting the status that actually went on the wire.
//
// Informational responses are the exception. httputil.ReverseProxy forwards
// every 1xx the upstream sends through this method, and net/http lets any
// number of them precede the final status, so they are passed on without
// being recorded. 101 Switching Protocols is not informational in that sense:
// it ends the HTTP exchange, so it is latched like any other final status.
func (r *responseRecorder) WriteHeader(code int) {
	if code >= 100 && code <= 199 && code != http.StatusSwitchingProtocols {
		r.ResponseWriter.WriteHeader(code)
		return
	}
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
		if r.onHijack != nil {
			r.onHijack()
		}
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
// just inside withRequestID and the auditor's WithRequestInfo, so the record
// carries the request's id and verb, and it exists whatever the rest of the
// chain does — including a handler that panics, which is recorded and then
// re-panicked for the server's own recovery to deal with.
//
// A long-running request also gets a record when its headers go out, mirroring
// the audit stage ResponseStarted: a watch or an exec that streams for hours
// would otherwise be invisible until it ended.
func (p *Proxy) withRequestLifecycle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		req = reqctx.WithTerminationHolder(req)
		req = reqctx.WithDecisionHolder(req)
		ctx := req.Context()

		// The verb and scope labels come from the RequestInfo the auditor's
		// WithRequestInfo resolved ahead of this filter, and the long-running
		// rule is the audit package's own, so this record and the audit event
		// agree on a watch or an exec. Both projections collapse anything
		// outside the documented sets, so a client cannot mint a series.
		info, _ := genericapirequest.RequestInfoFrom(ctx)
		verb, scope := metrics.VerbFor(info), metrics.ScopeFor(info)
		longRunning := audit.IsLongRunning(req)

		rec := &responseRecorder{ResponseWriter: w}
		established := false
		if longRunning {
			// A stream is open once its response has begun: headers written,
			// or the connection hijacked for an upgrade. Either path marks it
			// exactly once, and the gauge is released in the defer below.
			establish := func() {
				if !established {
					established = true
					p.metrics.LongRunningEstablished(verb, scope)
				}
			}
			rec.onStart = func(code int) {
				logging.Emit(ctx, p.requestLogger, logging.EventRequestResponseStarted,
					slog.Int("http_status", code),
					slog.Int64("time_to_headers_ms", time.Since(start).Milliseconds()))
				// Only a success status opens a stream: a refused watch (401,
				// 403) and a redirected upgrade (3xx) wrote headers but no
				// stream exists. 101 is the upgrade acknowledgement.
				if code == http.StatusSwitchingProtocols ||
					(code >= http.StatusOK && code < http.StatusMultipleChoices) {
					establish()
				}
			}
			rec.onHijack = establish
		}

		// Counted before the handler runs, released in the defer whatever the
		// handler does, so a panic cannot leak the gauge.
		p.metrics.RequestStarted()

		defer func() {
			panicked := recover()
			classified := reqctx.Termination(req)
			term := classifyTermination(panicked, rec.hijacked, ctx.Err(), classified)
			status := wireStatus(rec, panicked, term)
			duration := time.Since(start)

			logging.Emit(ctx, p.requestLogger, logging.EventRequestResponseCompleted,
				completionAttrs(rec, status, term, classified, duration)...)

			// One request, one record, one observation: the metric is built
			// from the same status and termination as the record.
			p.metrics.RequestFinished(metrics.RequestObservation{
				Verb:        verb,
				Scope:       scope,
				Status:      status,
				Termination: term,
				Duration:    duration,
				LongRunning: longRunning,
				Established: established,
				Hijacked:    rec.hijacked,
			})

			if panicked != nil {
				panic(panicked)
			}
		}()

		next.ServeHTTP(rec, req)
	})
}

// classifyTermination decides how a request ended from what the lifecycle
// filter can observe once the handler is done: a recovered panic, a hijacked
// connection, the request context's error, and the termination a handler
// deeper in the chain classified.
func classifyTermination(panicked any, hijacked bool, ctxErr error, classified reqctx.TerminationRecord) metrics.Termination {
	switch {
	// An http.ErrAbortHandler panic is not a fault: it is how
	// httputil.ReverseProxy reports a response copy that failed after the
	// headers went out. Whether the client went away or the upstream
	// connection broke is then decided exactly as it is for a request that
	// never panicked, so the two cases below classify it.
	case panicked != nil && !isAbortHandler(panicked):
		return metrics.TerminationPanic
	case hijacked:
		return metrics.TerminationHijacked
	case ctxErr != nil:
		return metrics.TerminationClientCancel
	case panicked != nil:
		// Aborted with the client still attached: the stream broke on the
		// upstream side.
		return metrics.TerminationUpstreamReset
	case classified.Kind != "":
		// Set by handleUpstreamError for an upstream failure.
		return classified.Kind
	}
	return metrics.TerminationNormal
}

// wireStatus is the status the client was actually answered with. A handler
// that returned without writing anything is answered with a 200 by net/http
// itself, unless the client had already gone: then the handler wrote nothing
// on purpose and no answer reached anyone. Zero is kept wherever no response
// went out -- that, a hijacked connection, or a panic that made the server
// drop the connection -- and is rendered as code="none" on the requests
// counter.
func wireStatus(rec *responseRecorder, panicked any, term metrics.Termination) int {
	if !rec.wrote && !rec.hijacked && panicked == nil && term != metrics.TerminationClientCancel {
		return http.StatusOK
	}
	return rec.status
}

// completionAttrs builds the request.response.completed record.
func completionAttrs(rec *responseRecorder, status int, term metrics.Termination, classified reqctx.TerminationRecord, duration time.Duration) []slog.Attr {
	attrs := []slog.Attr{
		slog.Int("http_status", status),
		slog.Int64("duration_ms", duration.Milliseconds()),
		slog.String("termination", string(term)),
	}
	// A hijacked connection is no longer described by the recorder: the
	// handler wrote to the socket directly, so a byte count of zero would be a
	// claim rather than a measurement.
	if !rec.hijacked {
		attrs = append(attrs, slog.Int64("response_bytes", rec.bytes))
	}
	// The classified reason travels with its termination, so a query on the
	// terminal record alone can tell an upstream failure from an ordinary
	// completion.
	if term == classified.Kind && classified.Reason != "" {
		attrs = append(attrs, slog.String("reason", string(classified.Reason)))
	}
	return attrs
}
