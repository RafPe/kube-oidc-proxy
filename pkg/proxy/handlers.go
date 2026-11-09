// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
)

// warnReasonHeadersDropped is the limiter bucket the dropped-header warning
// draws from. It is a bucket key rather than a record field, so it is not part
// of the closed reason value set.
const warnReasonHeadersDropped = "headers_dropped"

// Why impersonation was not applied to a request, as reported by
// request.impersonation.skipped.
const (
	skipReasonDisabled    = "disabled"
	skipReasonPassthrough = "passthrough"
)

// userFromContext returns the identity the request presented, or nil when it
// was refused before one was established.
func userFromContext(req *http.Request) authuser.Info {
	info, ok := genericapirequest.UserFrom(req.Context())
	if !ok {
		return nil
	}
	return info
}

// withHandlers composes the request filter chain around the reverse proxy,
// outermost last.
func (p *Proxy) withHandlers(handler http.Handler) http.Handler {
	handler = p.auditor.WithRequest(handler)
	handler = p.withImpersonateRequest(handler)
	handler = p.withAuthenticateRequest(handler)
	handler = p.withSanitizedForwardHeaders(handler)
	handler = p.withRequestLifecycle(handler)
	// Resolved before the lifecycle filter and the error handler, both of which
	// run outside the audit chain and need the request's verb and resource.
	handler = p.auditor.WithRequestInfo(handler)
	handler = p.withRequestID(handler)

	return handler
}

// withSanitizedForwardHeaders enforces the trusted-proxy contract on the
// forwarding headers before anything downstream reads them: the audit filters
// fill sourceIPs from these headers, the access log resolves the client IP
// from them, and the reverse proxy forwards them to the API server. Only the
// request-id filter runs ahead of it, so every path — including the
// unauthenticated audit chain, which runs inside withAuthenticateRequest —
// sees sanitized headers.
func (p *Proxy) withSanitizedForwardHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		inboundXFF := req.Header.Get(reqctx.HeaderForwardedFor)
		inboundRealIP := req.Header.Get(reqctx.HeaderRealIP)

		req = reqctx.WithResolvedClient(req, p.trustedProxies)

		if inboundXFF != "" || inboundRealIP != "" {
			p.logForwardHeaders(req, inboundXFF, inboundRealIP)
		}

		handler.ServeHTTP(rw, req)
	})
}

// logForwardHeaders reports what the trusted-proxy contract did to the inbound
// forwarding headers, so an operator can tell a misconfigured trusted-proxy
// list from a client spoofing its address. It runs only when the client
// actually sent one of the headers.
//
// A rewrite and a drop are not exclusive: X-Real-Ip is always removed, so a
// request that also had its X-Forwarded-For collapsed produces both records.
// Only the drop is token-bucketed; it is the one an untrusted client can
// produce on every request.
func (p *Proxy) logForwardHeaders(req *http.Request, inboundXFF, inboundRealIP string) {
	srcIP := reqctx.ClientIP(req)
	forwardedFor := slog.String("forwarded_for_untrusted", logging.Sanitize(inboundXFF))

	if outboundXFF := req.Header.Get(reqctx.HeaderForwardedFor); outboundXFF != "" && outboundXFF != inboundXFF {
		logging.Emit(req.Context(), p.requestLogger, logging.EventRequestHeadersRewritten,
			slog.String("src_ip", srcIP), forwardedFor)
	}

	// Sorted, and lower-cased as the wire format writes them, so the field is
	// queryable by exact match rather than by however the client spelled it.
	var dropped []string
	if inboundXFF != "" && req.Header.Get(reqctx.HeaderForwardedFor) == "" {
		dropped = append(dropped, strings.ToLower(reqctx.HeaderForwardedFor))
	}
	if inboundRealIP != "" {
		dropped = append(dropped, strings.ToLower(reqctx.HeaderRealIP))
	}
	if len(dropped) == 0 || !p.warnLimiter.Allow(warnReasonHeadersDropped) {
		return
	}
	slices.Sort(dropped)

	attrs := []slog.Attr{slog.String("src_ip", srcIP), slog.Any("dropped_headers", dropped)}
	// A client that sent only X-Real-Ip has no forwarded chain to report, and
	// the field must never carry a value that did not come from one.
	if inboundXFF != "" {
		attrs = append(attrs, forwardedFor)
	}
	logging.Emit(req.Context(), p.requestLogger, logging.EventRequestHeadersDropped, attrs...)
}

// withAuthenticateRequest adds the proxy authentication handler to a chain.
func (p *Proxy) withAuthenticateRequest(handler http.Handler) http.Handler {
	tokenReviewHandler := p.withTokenReview(handler)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// An authenticator is handed a context and answers with a user, so it
		// has no way to name itself on the request. The holder placed here is
		// how the issuer that accepts the token reports its name back, without
		// it travelling in the identity's extras and out as an impersonation
		// header; it is read back below.
		ctx, issuer := authn.WithIssuerHolder(req.Context())
		req = req.WithContext(ctx)

		info, ok, err := p.oidcRequestAuthenticator.AuthenticateRequest(req)
		if err != nil {
			// An error here means a token was present and failed validation;
			// an absent or unparseable token yields ok == false with a nil
			// error. The error text itself stays out of the record: the denial
			// is reported by reason, and a validation message is attacker
			// influenced.
			p.metrics.AuthenticationAttempt(metrics.AuthMethodOIDC, metrics.AuthRejected)
			logging.Emit(req.Context(), p.oidcLogger, logging.EventAuthnOIDCFailed,
				slog.String("src_ip", reqctx.ClientIP(req)), slog.String("reason", string(metrics.ReasonUnauthorized)))

			// Since we have failed OIDC auth, we will try a token review, if enabled.
			// Routing is deliberately unchanged: falling through to token
			// passthrough is documented alpha behaviour, not a defect.
			tokenReviewHandler.ServeHTTP(rw, req)
			return
		}

		if !ok {
			p.metrics.AuthenticationAttempt(metrics.AuthMethodNone, metrics.AuthRejected)
			p.handleError(rw, req, errUnauthorized)
			return
		}

		p.metrics.AuthenticationAttempt(metrics.AuthMethodOIDC, metrics.AuthAccepted)

		// Attribute the request to the issuer that accepted its token, for this
		// record and for every access record the request goes on to produce.
		req = reqctx.WithIssuerName(req, issuer.Name())

		logging.Emit(req.Context(), p.oidcLogger, logging.EventAuthnOIDCSucceeded,
			slog.String("issuer_name", logging.Bound(issuer.Name(), logging.MaxIdentity)))

		// The token was accepted, so every record from here on -- including a
		// rejection by the reserved-identity guard -- reports the OIDC path.
		req = reqctx.WithAuthMethod(req, metrics.AuthMethodOIDC)

		// Add the user info to the request context. Done before the
		// reserved-identity check so a rejection is audited against the identity
		// that was presented.
		req = req.WithContext(genericapirequest.WithUser(req.Context(), info.User))

		if err := checkReservedIdentity(info.User, p.allowedReservedGroups); err != nil {
			p.handleError(rw, req, err)
			return
		}

		handler.ServeHTTP(rw, req)
	})
}

// checkReservedIdentity refuses an identity that a token claim must never be
// able to produce. system: is reserved by Kubernetes: system:masters is
// cluster-admin by default, and system:serviceaccount:<ns>:<name> is any
// service account, both of which this proxy is granted blanket impersonate
// rights over. Kubernetes does not enforce this on claim mappings.
//
// Username has no exception: even system:authenticated can be granted rights by
// an RBAC binding naming it as a User. Groups permit exactly AllAuthenticated,
// because withImpersonateRequest appends it to every request anyway, so an IdP
// that also emits it must not 403 the whole cluster.
//
// The identity is refused, not stripped: a caller quietly served without the
// group they claimed has been told the wrong thing about who they are, and the
// resulting RBAC denial then looks like a policy bug.
//
// This is not implemented as UserValidationRules (CEL) on the JWTAuthenticator,
// the Kubernetes-native option, because a validation-rule failure surfaces as an
// authentication error and withAuthenticateRequest routes err != nil into the
// token-review path: with --token-passthrough on, the rejection would be
// swallowed and the request silently retried against TokenReview.
//
// allowedGroups names reserved groups the operator has explicitly permitted.
// It applies to groups only: a reserved username has no legitimate use, so
// there is deliberately no way to allow one short of disabling the guard.
func checkReservedIdentity(info authuser.Info, allowedGroups sets.Set[string]) error {
	if strings.HasPrefix(info.GetName(), ReservedIdentityPrefix) {
		return fmt.Errorf("%w: username %q", errReservedIdentity, info.GetName())
	}

	for _, group := range info.GetGroups() {
		if group == authuser.AllAuthenticated || allowedGroups.Has(group) {
			continue
		}
		if strings.HasPrefix(group, ReservedIdentityPrefix) {
			return fmt.Errorf("%w: group %q", errReservedIdentity, group)
		}
	}

	return nil
}

// withTokenReview will attempt a token review on the incoming request, if
// enabled.
func (p *Proxy) withTokenReview(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if !p.config.TokenPassthrough {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		if !p.reviewToken(req) {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		// OIDC did not accept the token, so the bearer authenticator left the
		// Authorization header in place; the request is forwarded with the
		// client's own token. That decides how it is forwarded, so the
		// impersonation filter and RoundTrip both see it settled: no outbound
		// identity, and no proxy-authenticated inbound one either.
		req = reqctx.WithAuthMethod(req, metrics.AuthMethodTokenReview)
		req = reqctx.WithImpersonation(req, &reqctx.Impersonation{})

		handler.ServeHTTP(rw, req)
	})
}
