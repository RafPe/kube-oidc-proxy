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
	"syscall"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/accesslog"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

// refuse answers a request the proxy will not forward -- refused, or failed
// before it could be forwarded -- by classifying err, recording the access
// decision, auditing the refusal and writing the response. The filters call
// it; a failure of the forwarded request itself goes to handleUpstreamError.
func (p *Proxy) refuse(rw http.ResponseWriter, r *http.Request, err error) {
	// Every refusal of a request that did authenticate is audited through the
	// ordinary request chain rather than the failed-authentication one: the
	// caller has already put the identity in the request context, so the
	// event names who was refused.
	deny := func(status int, body string) {
		p.auditor.WithRequest(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, body, status)
		})).ServeHTTP(rw, r)
	}

	// A request that did not authenticate is audited as a failed
	// authentication, against the anonymous user, because no identity was
	// established.
	unauthenticated := func() {
		p.auditor.WithFailedAuthentication(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
		})).ServeHTTP(rw, r)
	}

	if err == nil {
		// Nothing was decided about a request, so nothing is recorded about
		// one; the proxy bug is still reported.
		logging.EmitLevel(r.Context(), p.requestLogger, logging.EventRequestHandlerFailed, slog.LevelError,
			slog.String("reason", string(metrics.ReasonInternalError)),
			slog.String("error_message", "error handler called with nil error"))
		http.Error(rw, "", http.StatusInternalServerError)
		return
	}

	// The access record carries the classified reason, so every branch below
	// records why the request was refused before it writes the response.
	switch {
	// The client went away while its credential or its impersonation was
	// being reviewed: cancelled, or its own deadline passed. Nothing is
	// written back; the connection is already going away. No upstream call
	// was made, so there is no upstream record either: the review that saw it
	// reported authn.tokenreview.failed or authz.sar.failed with
	// reason=client_canceled, and the access record carries the same reason.
	// Checked first, because the review failure wraps the cancellation.
	case errors.Is(err, context.Canceled),
		(errors.Is(err, errTokenReviewUnavailable) || errors.Is(err, subjectaccessreview.ErrCreateSubjectAccessReview)) &&
			r.Context().Err() != nil:
		p.logDenied(r, metrics.ReasonClientCanceled, err)

	case errors.Is(err, errUnauthorized):
		p.logDenied(r, metrics.ReasonUnauthorized, err)
		unauthenticated()

	// The TokenReview could not be answered. The proxy fails closed, so the
	// client sees the same 401 as for a rejected token, but the access record
	// carries the dependency failure authn.tokenreview.failed reported.
	case errors.Is(err, errTokenReviewUnavailable):
		p.logDenied(r, metrics.ReasonAuthenticationDependencyError, err)
		unauthenticated()

	// Authenticated, but the identity is one a token must never mint: an
	// exploit attempt or a badly broken claim mapping, not an ordinary denial.
	case errors.Is(err, errReservedIdentity):
		p.logAnomaly(r, metrics.ReasonReservedIdentity)
		p.logDenied(r, metrics.ReasonReservedIdentity, err)
		// The client body carries no claim values; they are logged and
		// audited instead.
		deny(http.StatusForbidden, "identities with the reserved \"system:\" prefix are not accepted from an authentication token")

	// The token carried no username claim.
	case errors.Is(err, errNoName):
		p.logDenied(r, metrics.ReasonNoUsernameClaim, err)
		deny(http.StatusForbidden, "Username claim not available in OIDC Issuer response")

	// Groups, uid or extras with no user to refine. Like an unknown
	// impersonation header below, it is refused by its shape before any
	// SubjectAccessReview, so it answers with the same 400.
	case errors.Is(err, subjectaccessreview.ErrNoImpersonationUser):
		p.logDenied(r, metrics.ReasonMalformedImpersonation, err)
		deny(http.StatusBadRequest, err.Error())

	// An Impersonate- header of a kind the proxy does not know. Not logged as
	// a failure of the proxy's own: a client can send it on every request.
	case errors.Is(err, subjectaccessreview.ErrUnknownImpersonationHeader):
		p.logDenied(r, metrics.ReasonMalformedImpersonation, err)
		deny(http.StatusBadRequest, err.Error())

	// Far more impersonation header values than any client legitimately
	// sends: a resource-exhaustion attempt against the SubjectAccessReview
	// path, refused before any review was sent. A request-shape rejection,
	// not an authorization denial.
	case errors.Is(err, subjectaccessreview.ErrTooManyImpersonationHeaderValues):
		p.logAnomaly(r, metrics.ReasonTooManyImpersonationValues)
		p.logDenied(r, metrics.ReasonTooManyImpersonationValues, err)
		deny(http.StatusRequestHeaderFieldsTooLarge, err.Error())

	// The requester may not impersonate the requested identity. Classified by
	// typed error (errors.Is), not by message text.
	case errors.Is(err, subjectaccessreview.ErrImpersonationNotAllowed):
		p.logDenied(r, metrics.ReasonImpersonationDenied, err)
		deny(http.StatusForbidden, err.Error())

	// The SubjectAccessReview could not be submitted, or the API server did
	// not answer within the proxy's budget. authz.sar.failed has already
	// reported it at ERROR, so this is not a request.handler.failed of the
	// proxy's own: the access record carries the dependency reason instead.
	case errors.Is(err, subjectaccessreview.ErrCreateSubjectAccessReview):
		p.logDenied(r, metrics.ReasonAuthorizationDependencyError, err)
		deny(http.StatusInternalServerError, "")

	// Server or unknown error.
	default:
		p.failInternal(rw, r, err)
	}
}

// handleUpstreamError is the reverse proxy's ErrorHandler. RoundTrip wrote the
// request's access decision before it called the API server, so a failure
// here is not a second decision: it is reported on the upstream component, and
// the termination it classifies is handed to the lifecycle filter for the
// terminal record.
func (p *Proxy) handleUpstreamError(rw http.ResponseWriter, r *http.Request, err error) {
	switch {
	// The client went away before the upstream response completed. Nothing is
	// written back; the connection is already going away.
	case errors.Is(err, context.Canceled):
		logging.Emit(r.Context(), p.upstreamLogger, logging.EventUpstreamRequestCanceled,
			slog.String("reason", string(metrics.ReasonClientCanceled)))

	// The call to the API server could not be made or completed.
	case isUpstreamTransportError(err):
		term := upstreamTermination(err)
		reqctx.MarkTermination(r, term, metrics.ReasonUpstreamError)
		logging.Emit(r.Context(), p.upstreamLogger, logging.EventUpstreamRequestFailed,
			slog.String("reason", string(metrics.ReasonUpstreamError)), slog.String("termination", string(term)),
			logging.ErrAttr(err))
		http.Error(rw, "", http.StatusBadGateway)

	// Not the transport: RoundTrip found no forwarding decision on the
	// request, or the reverse proxy could not complete a protocol upgrade.
	// Both are the proxy's own failure.
	default:
		p.failInternal(rw, r, err)
	}
}

// isUpstreamTransportError reports whether the error came from the transport
// carrying the request to the API server rather than from the proxy itself.
// Any net.Error counts -- *net.OpError, *url.Error and syscall.Errno all are
// one -- plus the stream ends and certificate failures that are not.
func isUpstreamTransportError(err error) bool {
	var (
		netErr  net.Error
		certErr *tls.CertificateVerificationError
	)
	return errors.As(err, &netErr) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.As(err, &certErr)
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

// failInternal answers a failure the proxy itself is responsible for. The
// error text stays server-side, recorded as request.handler.failed bounded and
// sanitized; the client receives an empty 500 body and the access record
// carries reason=internal_error.
func (p *Proxy) failInternal(rw http.ResponseWriter, r *http.Request, err error) {
	logging.EmitLevel(r.Context(), p.requestLogger, logging.EventRequestHandlerFailed, slog.LevelError,
		slog.String("reason", string(metrics.ReasonInternalError)), logging.ErrAttr(err))
	p.logDenied(r, metrics.ReasonInternalError, err)
	http.Error(rw, "", http.StatusInternalServerError)
}

// logAnomaly reports a rejection that indicates an exploit attempt or gross
// misconfiguration rather than an ordinary denial. It is token-bucketed per
// reason, because a client can produce these without bound; the access record,
// which is never sampled, still carries the outcome.
func (p *Proxy) logAnomaly(r *http.Request, reason metrics.Reason) {
	if !p.warnLimiter.Allow(logging.WarningKey{Event: logging.EventRequestAnomalyDetected, Reason: string(reason)}) {
		return
	}

	logging.Emit(r.Context(), p.requestLogger, logging.EventRequestAnomalyDetected,
		slog.String("src_ip", reqctx.ClientIP(r)), slog.String("reason", string(reason)))
}

// logDenied writes the access record for a refused request. The impersonation
// target, when the error names one, is taken from the typed error rather than
// parsed back out of the client-facing message.
func (p *Proxy) logDenied(r *http.Request, reason metrics.Reason, err error) {
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
