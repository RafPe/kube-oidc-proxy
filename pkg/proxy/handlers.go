// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	stdcontext "context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
	accesslogging "github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

// reservedIdentityPrefix is the username/group prefix Kubernetes reserves for
// its own identities.
const reservedIdentityPrefix = "system:"

// How a request authenticated, as reported by the access record's auth_method.
const (
	authMethodOIDC        = "oidc"
	authMethodTokenReview = "tokenreview"
	authMethodNone        = "none"
)

// The closed set of access-record reasons this package classifies. A denial
// carries exactly one of them, so a query never has to match on message text.
const (
	reasonUnauthorized               = "unauthorized"
	reasonReservedIdentity           = "reserved_identity"
	reasonNoUsernameClaim            = "no_username_claim"
	reasonImpersonationDenied        = "impersonation_denied"
	reasonTooManyImpersonationValues = "too_many_impersonation_values"
	reasonClientCanceled             = "client_canceled"
	reasonInternalError              = "internal_error"
)

// authMethodKey is the context key carrying how the request authenticated. It
// is set by the handler that accepted the credential and read by the access
// record, which runs after the decision on both the success and failure paths.
type authMethodKey struct{}

// withAuthMethod records how the request authenticated.
func withAuthMethod(req *http.Request, method string) *http.Request {
	return req.WithContext(stdcontext.WithValue(req.Context(), authMethodKey{}, method))
}

// authMethodFrom returns how the request authenticated. A request refused
// before any authenticator accepted it has none.
func authMethodFrom(req *http.Request) string {
	method, _ := req.Context().Value(authMethodKey{}).(string)
	if method == "" {
		return authMethodNone
	}
	return method
}

// userFromContext returns the identity the request presented, or nil when it
// was refused before one was established.
func userFromContext(req *http.Request) authuser.Info {
	info, ok := genericapirequest.UserFrom(req.Context())
	if !ok {
		return nil
	}
	return info
}

// impersonationTargetKind maps the kind as the client-facing denial message
// renders it onto the closed target_kind value set.
func impersonationTargetKind(kind string) string {
	if kind == "extra info" {
		return "extra"
	}
	return kind
}

func (p *Proxy) withHandlers(handler http.Handler) http.Handler {
	// Set up proxy handlers
	handler = p.auditor.WithRequest(handler)
	handler = p.withImpersonateRequest(handler)
	handler = p.withAuthenticateRequest(handler)
	handler = p.withSanitizedForwardHeaders(handler)
	handler = p.withRequestID(handler)

	// Add the auditor backend as a shutdown hook
	p.hooks.AddPreShutdownHook("AuditBackend", p.auditor.Shutdown)

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
		handler.ServeHTTP(rw, context.SanitizeForwardHeaders(req))
	})
}

// withAuthenticateRequest adds the proxy authentication handler to a chain.
func (p *Proxy) withAuthenticateRequest(handler http.Handler) http.Handler {
	tokenReviewHandler := p.withTokenReview(handler)

	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Auth request and handle unauthed
		info, ok, err := p.oidcRequestAuther.AuthenticateRequest(req)
		if err != nil {
			// An error here means a token was present and failed validation;
			// an absent or unparseable token yields ok == false with a nil
			// error. Log it at the level operators run at, not V(5).
			var remoteAddr string
			req, remoteAddr = context.RemoteAddr(req)
			klog.V(2).Infof("failed to authenticate request (%s): %s", remoteAddr, err)

			// Since we have failed OIDC auth, we will try a token review, if enabled.
			// Routing is deliberately unchanged: falling through to token
			// passthrough is documented alpha behaviour, not a defect.
			tokenReviewHandler.ServeHTTP(rw, req)
			return
		}

		// Failed authorization
		if !ok {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		var remoteAddr string
		req, remoteAddr = context.RemoteAddr(req)

		klog.V(4).Infof("authenticated request: %s", remoteAddr)

		// The token was accepted, so every record from here on -- including a
		// rejection by the reserved-identity guard -- reports the OIDC path.
		req = withAuthMethod(req, authMethodOIDC)

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
	if strings.HasPrefix(info.GetName(), reservedIdentityPrefix) {
		return fmt.Errorf("%w: username %q", errReservedIdentity, info.GetName())
	}

	for _, group := range info.GetGroups() {
		if group == authuser.AllAuthenticated || allowedGroups.Has(group) {
			continue
		}
		if strings.HasPrefix(group, reservedIdentityPrefix) {
			return fmt.Errorf("%w: group %q", errReservedIdentity, group)
		}
	}

	return nil
}

// withTokenReview will attempt a token review on the incoming request, if
// enabled.
func (p *Proxy) withTokenReview(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// If token review is not enabled then error.
		if !p.config.TokenReview {
			p.handleError(rw, req, errUnauthorized)
			return
		}

		// Attempt to passthrough request if valid token
		if !p.reviewToken(rw, req) {
			// Token review failed so error
			p.handleError(rw, req, errUnauthorized)
			return
		}

		// Set no impersonation headers and re-add removed headers.
		req = withAuthMethod(req, authMethodTokenReview)
		req = context.WithNoImpersonation(req)

		handler.ServeHTTP(rw, req)
	})
}

// withImpersonateRequest adds the impersonation request handler to the chain.
func (p *Proxy) withImpersonateRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// If no impersonation has already been set, return early
		if context.NoImpersonation(req) {
			handler.ServeHTTP(rw, req)
			return
		}

		var targetForContext authuser.Info

		var remoteAddr string
		req, remoteAddr = context.RemoteAddr(req)

		// If we have disabled impersonation we can forward the request right away
		if p.config.DisableImpersonation {
			klog.V(2).Infof("passing on request with no impersonation: %s", remoteAddr)
			// Indicate we need to not use impersonation.
			req = context.WithNoImpersonation(req)
			handler.ServeHTTP(rw, req)
			return
		}

		user, ok := genericapirequest.UserFrom(req.Context())
		// No name available so reject request
		if !ok || len(user.GetName()) == 0 {
			p.handleError(rw, req, errNoName)
			return
		}

		userForContext := user

		if p.hasImpersonation(req.Header) {
			// if impersonation headers are present, let's check to see
			// if the user is authorized to perform the impersonation
			target, err := p.subjectAccessReviewer.CheckAuthorizedForImpersonation(req, user)

			if err != nil {
				p.handleError(rw, req, err)
				return
			}

			if target != nil {
				// TODO - store original context for logging
				user = target
				targetForContext = target
			}
		}

		// Defensively copy the authenticator-owned collections before enriching
		// them. user.Info implementations are not required to return fresh
		// slices/maps, so appending to GetGroups() or writing into GetExtra()
		// could otherwise mutate cached or shared authenticator state.
		groups := slices.Clone(user.GetGroups())
		extra := cloneExtra(user.GetExtra())

		// Ensure group contains allauthenticated builtin
		if !slices.Contains(groups, authuser.AllAuthenticated) {
			groups = append(groups, authuser.AllAuthenticated)
		}

		// If client IP user extra header option set then append the remote client
		// address.
		if p.config.ExtraUserHeadersClientIPEnabled {
			klog.V(6).Infof("adding impersonate extra user header %s (%s)",
				UserHeaderClientIPKey, remoteAddr)

			extra[UserHeaderClientIPKey] = append(extra[UserHeaderClientIPKey], remoteAddr)
		}

		// Add custom extra user headers to impersonation request.
		for k, vs := range p.config.ExtraUserHeaders {
			for _, v := range vs {
				klog.V(6).Infof("adding impersonate extra user header %s (%s)",
					k, remoteAddr)

				extra[k] = append(extra[k], v)
			}
		}

		if targetForContext != nil {
			// add the original user's information as extra headers
			// so they're recorded in the API server's audit log
			extra["originaluser.jetstack.io-user"] = []string{userForContext.GetName()}

			if origGroups := userForContext.GetGroups(); len(origGroups) > 0 {
				extra["originaluser.jetstack.io-groups"] = slices.Clone(origGroups)
			}

			if userForContext.GetUID() != "" {
				extra["originaluser.jetstack.io-uid"] = []string{userForContext.GetUID()}
			}

			if len(userForContext.GetExtra()) > 0 {
				jsonExtras, errJSONMarshal := json.Marshal(userForContext.GetExtra())
				if errJSONMarshal != nil {
					p.handleError(rw, req, errJSONMarshal)
					return
				}
				extra["originaluser.jetstack.io-extra"] = []string{string(jsonExtras)}
			}
		}

		conf := &context.ImpersonationRequest{
			ImpersonationConfig: &transport.ImpersonationConfig{
				UserName: user.GetName(),
				UID:      user.GetUID(),
				Groups:   groups,
				Extra:    extra,
			},
			InboundUser:      &userForContext,
			ImpersonatedUser: &targetForContext,
		}

		// Add the impersonation configuration to the context.
		req = context.WithImpersonationConfig(req, conf)
		handler.ServeHTTP(rw, req)
	})
}

// newErrorHandler returns a handler failed requests.
func (p *Proxy) newErrorHandler() func(rw http.ResponseWriter, r *http.Request, err error) {

	unauthedHandler := audit.NewUnauthenticatedHandler(p.auditor, func(rw http.ResponseWriter, r *http.Request) {
		klog.V(2).Infof("unauthenticated user request %s", r.RemoteAddr)
		http.Error(rw, "Unauthorized", http.StatusUnauthorized)
	})

	// Audited through the ordinary request chain rather than the
	// failed-authentication one: the request authenticated successfully and was
	// then refused, and the caller has already put the identity in the request
	// context. The client body carries no claim values; they are logged and
	// audited instead.
	forbiddenHandler := audit.NewForbiddenHandler(p.auditor, func(rw http.ResponseWriter, r *http.Request) {
		http.Error(rw, "identities with the reserved \"system:\" prefix are not accepted from an authentication token", http.StatusForbidden)
	})

	return func(rw http.ResponseWriter, r *http.Request, err error) {

		if err == nil {
			klog.Error("error was called with no error")
			http.Error(rw, "", http.StatusInternalServerError)
			return
		}

		// The access record carries the classified reason, so every branch below
		// records why the request was refused before it writes the response.
		var netErr net.Error

		switch {

		// Failed auth
		case errors.Is(err, errUnauthorized):
			// If Unauthorized then error and report to audit
			p.logDenied(r, reasonUnauthorized, err)
			unauthedHandler.ServeHTTP(rw, r)
			return

			// Authenticated, but the identity is one a token must never mint.
		case errors.Is(err, errReservedIdentity):
			klog.V(2).Infof("rejecting reserved identity (%s): %s", r.RemoteAddr, err)
			p.logDenied(r, reasonReservedIdentity, err)
			forbiddenHandler.ServeHTTP(rw, r)
			return

			// No name given or available in oidc request
		case errors.Is(err, errNoName):
			klog.V(2).Infof("no name available in oidc info %s", r.RemoteAddr)
			p.logDenied(r, reasonNoUsernameClaim, err)
			http.Error(rw, "Username claim not available in OIDC Issuer response", http.StatusForbidden)
			return

			// No impersonation configuration found in context
		case errors.Is(err, errNoImpersonationConfig):
			klog.Errorf("impersonation configuration missing from request context (%s): %s", r.RemoteAddr, err)
			p.logDenied(r, reasonInternalError, err)
			http.Error(rw, "", http.StatusInternalServerError)
			return

			// No impersonation user found
		case errors.Is(err, subjectaccessreview.ErrorNoImpersonationUserFound):
			p.logDenied(r, reasonInternalError, err)
			http.Error(rw, subjectaccessreview.ErrorNoImpersonationUserFound.Error(), http.StatusInternalServerError)
			return

			// Request carries more impersonation header values than the
			// configured cap. Refused before any SubjectAccessReview was sent;
			// this is a request-shape rejection, not an authorization denial.
		case errors.Is(err, subjectaccessreview.ErrTooManyImpersonationHeaderValues):
			klog.V(2).Infof("too many impersonation header values (%s): %s", r.RemoteAddr, err)
			p.logDenied(r, reasonTooManyImpersonationValues, err)
			http.Error(rw, err.Error(), http.StatusRequestHeaderFieldsTooLarge)
			return

			// Requester is not authorized to impersonate the requested identity.
			// Classified by typed error (errors.Is), not by message text.
		case errors.Is(err, subjectaccessreview.ErrImpersonationNotAllowed):
			klog.V(2).Infof("impersonation not authorized (%s): %s", r.RemoteAddr, err)
			p.logDenied(r, reasonImpersonationDenied, err)
			http.Error(rw, err.Error(), http.StatusForbidden)
			return

			// Client canceled the request (SAR or reverse-proxy). Nothing to
			// write back; the connection is already going away.
		case errors.Is(err, stdcontext.Canceled):
			klog.V(4).Infof("request canceled by client: %s", r.RemoteAddr)
			p.logDenied(r, reasonClientCanceled, err)
			return

			// The reverse proxy could not reach or complete the call to the API
			// server. The request was already admitted, and its access decision
			// was written by RoundTrip: an upstream failure is not a second
			// decision, so nothing is recorded here. Task 14 adds the upstream
			// event that carries the failure itself.
		case errors.As(err, &netErr):
			klog.Errorf("upstream request failed (%s): %s", r.RemoteAddr, err)
			http.Error(rw, "", http.StatusBadGateway)
			return

			// Server or unknown error. Details stay server-side; the client
			// receives an empty 500 body.
		default:
			klog.Errorf("unknown error (%s): %s", r.RemoteAddr, err)
			p.logDenied(r, reasonInternalError, err)
			http.Error(rw, "", http.StatusInternalServerError)
		}
	}
}

// logDenied writes the access record for a refused request. The impersonation
// target, when the error names one, is taken from the typed error rather than
// parsed back out of the client-facing message.
func (p *Proxy) logDenied(r *http.Request, reason string, err error) {
	d := accesslogging.Decision{
		Allowed:    false,
		Reason:     reason,
		AuthMethod: authMethodFrom(r),
		Inbound:    userFromContext(r),
	}

	var authErr *subjectaccessreview.ImpersonationAuthError
	if errors.As(err, &authErr) {
		d.TargetKind = impersonationTargetKind(authErr.Kind)
		d.TargetName = strings.Trim(authErr.Target, "'")
	}

	p.access.LogDecision(r, d)
}

// cloneExtra returns a deep copy of an authenticator-owned extra map: both the
// map and every value slice are freshly allocated, so subsequent enrichment can
// append to a value slice without mutating collections owned by the
// authenticator or the configuration caller. A nil input yields a non-nil,
// ready-to-write map.
func cloneExtra(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

func (p *Proxy) hasImpersonation(header http.Header) bool {
	for h := range header {
		if strings.HasPrefix(strings.ToLower(h), "impersonate-") {
			return true
		}
	}

	return false
}
