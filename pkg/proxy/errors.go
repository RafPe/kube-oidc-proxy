// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"syscall"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

// deniedResponse is the status and body an audited denial writes once the
// audit filters have recorded the refusal; it travels on the request context
// under deniedResponseKey because the audited handler is built once and the
// response differs per error.
type deniedResponse struct {
	status int
	body   string
}

type deniedResponseKey struct{}

// newErrorHandler returns a handler failed requests.
func (p *Proxy) newErrorHandler() func(rw http.ResponseWriter, r *http.Request, err error) {

	unauthedHandler := audit.NewUnauthenticatedHandler(p.auditor, func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	})

	// Every refusal of a request that did authenticate is audited through the
	// ordinary request chain rather than the failed-authentication one: the
	// caller has already put the identity in the request context, so the
	// event names who was refused. The response is decided per error below
	// and travels to the audited handler on the request context.
	auditedDenial := audit.NewForbiddenHandler(p.auditor, func(rw http.ResponseWriter, r *http.Request) {
		d, _ := r.Context().Value(deniedResponseKey{}).(deniedResponse)
		http.Error(rw, d.body, d.status)
	})
	deny := func(rw http.ResponseWriter, r *http.Request, status int, body string) {
		r = r.WithContext(context.WithValue(r.Context(), deniedResponseKey{}, deniedResponse{status: status, body: body}))
		auditedDenial.ServeHTTP(rw, r)
	}

	return func(rw http.ResponseWriter, r *http.Request, err error) {

		if err == nil {
			// Nothing was decided about a request, so nothing is recorded about
			// one; the proxy bug is still reported.
			logging.EmitLevel(r.Context(), logging.OrDiscard(p.logger), logging.EventRequestHandlerFailed, slog.LevelError,
				slog.String("reason", string(metrics.ReasonInternalError)),
				slog.String("error_message", "error handler called with nil error"))
			http.Error(rw, "", http.StatusInternalServerError)
			return
		}

		// The access record carries the classified reason, so every branch below
		// records why the request was refused before it writes the response.
		switch {

		// Failed auth
		case errors.Is(err, errUnauthorized):
			// If Unauthorized then error and report to audit
			p.logDenied(r, metrics.ReasonUnauthorized, err)
			unauthedHandler.ServeHTTP(rw, r)
			return

			// Authenticated, but the identity is one a token must never mint.
		case errors.Is(err, errReservedIdentity):
			// A token minting a system: identity is an exploit attempt or a
			// badly broken claim mapping, not an ordinary denial.
			p.logAnomaly(r, metrics.ReasonReservedIdentity)
			p.logDenied(r, metrics.ReasonReservedIdentity, err)
			// The client body carries no claim values; they are logged and
			// audited instead.
			deny(rw, r, http.StatusForbidden, "identities with the reserved \"system:\" prefix are not accepted from an authentication token")
			return

			// No name given or available in oidc request
		case errors.Is(err, errNoName):
			p.logDenied(r, metrics.ReasonNoUsernameClaim, err)
			deny(rw, r, http.StatusForbidden, "Username claim not available in OIDC Issuer response")
			return

			// No impersonation user found
		case errors.Is(err, subjectaccessreview.ErrNoImpersonationUser):
			p.logDenied(r, metrics.ReasonInternalError, err)
			deny(rw, r, http.StatusInternalServerError, subjectaccessreview.ErrNoImpersonationUser.Error())
			return

			// Request carries more impersonation header values than the
			// configured cap. Refused before any SubjectAccessReview was sent;
			// this is a request-shape rejection, not an authorization denial.
		case errors.Is(err, subjectaccessreview.ErrTooManyImpersonationHeaderValues):
			// Far more impersonation values than any client legitimately sends:
			// a resource-exhaustion attempt against the SubjectAccessReview path.
			p.logAnomaly(r, metrics.ReasonTooManyImpersonationValues)
			p.logDenied(r, metrics.ReasonTooManyImpersonationValues, err)
			deny(rw, r, http.StatusRequestHeaderFieldsTooLarge, err.Error())
			return

			// Requester is not authorized to impersonate the requested identity.
			// Classified by typed error (errors.Is), not by message text.
		case errors.Is(err, subjectaccessreview.ErrImpersonationNotAllowed):
			p.logDenied(r, metrics.ReasonImpersonationDenied, err)
			deny(rw, r, http.StatusForbidden, err.Error())
			return

			// Client canceled the request (SAR or reverse-proxy). Nothing to
			// write back; the connection is already going away.
		case errors.Is(err, context.Canceled):
			logging.Emit(r.Context(), logging.OrDiscard(p.upstreamLog), logging.EventUpstreamRequestCanceled,
				slog.String("reason", string(metrics.ReasonClientCanceled)))
			p.logDenied(r, metrics.ReasonClientCanceled, err)
			return

			// The reverse proxy could not reach or complete the call to the API
			// server. The request was already admitted, and its access decision
			// was written by RoundTrip: an upstream failure is not a second
			// decision, so none is recorded here. The failure is reported on its
			// own upstream record, and the termination it classifies is handed
			// to the lifecycle filter for the terminal record.
		case isUpstreamTransportError(err):
			term := upstreamTermination(err)
			reqctx.RecordTermination(r, term, metrics.ReasonUpstreamError)
			logging.Emit(r.Context(), logging.OrDiscard(p.upstreamLog), logging.EventUpstreamRequestFailed,
				slog.String("reason", string(metrics.ReasonUpstreamError)), slog.String("termination", string(term)),
				logging.ErrAttr(err))
			http.Error(rw, "", http.StatusBadGateway)
			return

			// Server or unknown error, including a missing impersonation
			// configuration and a SubjectAccessReview the proxy could not
			// submit. Details stay server-side; the client receives an empty
			// 500 body.
		default:
			p.logHandlerFailed(r, err)
			p.logDenied(r, metrics.ReasonInternalError, err)
			http.Error(rw, "", http.StatusInternalServerError)
		}
	}
}

// isUpstreamTransportError reports whether the error came from the transport
// carrying the request to the API server rather than from a decision the proxy
// made about it. The error handler is dual-use -- the authentication and
// impersonation filters call it directly, not only the reverse proxy -- so the
// test is by error type, never a catch-all: an unrecognised error stays a 500.
func isUpstreamTransportError(err error) bool {
	// A SubjectAccessReview the proxy could not submit wraps a client-go
	// transport error that satisfies net.Error, but the call that failed is
	// the proxy's own authorization dependency, not the hop to the API server:
	// the request is refused, not proxied, so it is a 500 and never a 502.
	if errors.Is(err, subjectaccessreview.ErrCreateSubjectAccessReview) {
		return false
	}

	var (
		netErr  net.Error
		opErr   *net.OpError
		urlErr  *url.Error
		certErr *tls.CertificateVerificationError
		errno   syscall.Errno
	)

	return errors.As(err, &netErr) || errors.As(err, &opErr) || errors.As(err, &urlErr) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.As(err, &errno) || errors.As(err, &certErr)
}

// upstreamTermination classifies an upstream transport failure into the closed
// termination set the terminal record reports, so an operator can tell an API
// server that is slow from one that is dropping connections without reading
// error text.
func upstreamTermination(err error) metrics.Termination {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return metrics.TerminationUpstreamTimeout
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return metrics.TerminationUpstreamReset
	}

	return metrics.TerminationProxyError
}

// logHandlerFailed reports a failure the proxy itself is responsible for. The
// error text is kept out of the client-facing body and recorded here instead,
// bounded and sanitized; the access record carries reason=internal_error.
func (p *Proxy) logHandlerFailed(r *http.Request, err error) {
	logging.EmitLevel(r.Context(), logging.OrDiscard(p.logger), logging.EventRequestHandlerFailed, slog.LevelError,
		slog.String("reason", string(metrics.ReasonInternalError)), logging.ErrAttr(err))
}

// logAnomaly reports a rejection that indicates an exploit attempt or gross
// misconfiguration rather than an ordinary denial. It is token-bucketed per
// reason, because a client can produce these without bound; the access record,
// which is never sampled, still carries the outcome.
func (p *Proxy) logAnomaly(r *http.Request, reason metrics.Reason) {
	if !p.warnLimiter.Allow(string(reason)) {
		return
	}

	logging.Emit(r.Context(), logging.OrDiscard(p.logger), logging.EventRequestAnomalyDetected,
		slog.String("src_ip", reqctx.ClientIP(r)), slog.String("reason", string(reason)))
}

// logDenied writes the access record for a refused request. The impersonation
// target, when the error names one, is taken from the typed error rather than
// parsed back out of the client-facing message.
func (p *Proxy) logDenied(r *http.Request, reason metrics.Reason, err error) {
	// RoundTrip writes the access record for an admitted request before the
	// upstream call, so a failure arriving after that -- a client that
	// cancelled, an upstream that broke -- has no decision left to make. Every
	// refusal below the error handler shares this guard, which keeps the
	// promise of one request.access.decided per request.
	if reqctx.DecisionRecorded(r) {
		return
	}

	d := accesslog.Decision{
		Allowed:    false,
		Reason:     reason,
		AuthMethod: reqctx.AuthMethod(r),
		Inbound:    userFromContext(r),
	}

	var authErr *subjectaccessreview.ImpersonationAuthError
	if errors.As(err, &authErr) {
		d.TargetKind = authErr.Kind
		d.TargetName = authErr.TargetName()
	}

	p.recordDecision(r, d)
}
