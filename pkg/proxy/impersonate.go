// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"

	authuser "k8s.io/apiserver/pkg/authentication/user"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/subjectaccessreview"
)

// withImpersonateRequest decides how an authenticated request is forwarded:
// as the identity the client asked to impersonate, once the
// SubjectAccessReviews allowed it, or as the inbound identity itself.
//
// Client Impersonate-* headers are checked and consumed only here, on the
// impersonating path. On the two paths that forward without the proxy's own
// credentials -- token passthrough and --disable-impersonation -- the headers
// travel on untouched and the API server authorizes them against the
// identity it authenticates: the client's own token, or anonymous.
func (p *Proxy) withImpersonateRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		// Token passthrough already decided this request: it is forwarded with
		// the client's own token.
		if reqctx.ImpersonationOf(req) != nil {
			logging.Emit(req.Context(), p.requestLogger, logging.EventRequestImpersonationSkipped,
				slog.String("skip_reason", skipReasonPassthrough))
			handler.ServeHTTP(rw, req)
			return
		}

		if p.config.DisableImpersonation {
			logging.Emit(req.Context(), p.requestLogger, logging.EventRequestImpersonationSkipped,
				slog.String("skip_reason", skipReasonDisabled))
			handler.ServeHTTP(rw, reqctx.WithImpersonation(req, &reqctx.Impersonation{InboundUser: userFromContext(req)}))
			return
		}

		inbound, ok := genericapirequest.UserFrom(req.Context())
		if !ok || len(inbound.GetName()) == 0 {
			p.handleError(rw, req, errNoName)
			return
		}

		// target is the identity the client asked to impersonate, once the
		// SubjectAccessReviews allowed it; nil when the request impersonates
		// nobody and the inbound identity is forwarded as itself.
		var target authuser.Info
		if subjectaccessreview.HasImpersonationHeaders(req.Header) {
			var err error
			target, err = p.subjectAccessReviewer.CheckAuthorizedForImpersonation(req, asAuthenticated(inbound))
			if err != nil {
				p.handleError(rw, req, err)
				return
			}

			// The client's headers have been authorized and become the
			// outbound identity below. They must not travel on the forwarded
			// request: client-go's impersonating round tripper leaves a request
			// that already carries Impersonate-User untouched, which would
			// forward them under the proxy's own credentials.
			req.Header = subjectaccessreview.StripImpersonationHeaders(req.Header)
		}

		outbound, err := p.outboundIdentity(req, inbound, target)
		if err != nil {
			p.handleError(rw, req, err)
			return
		}

		imp := &reqctx.Impersonation{
			Outbound:         outbound,
			InboundUser:      inbound,
			ImpersonatedUser: target,
		}

		logging.Emit(req.Context(), p.requestLogger, logging.EventRequestImpersonationApplied,
			slog.String("outbound_user", logging.Bound(outbound.UserName, logging.MaxIdentity)),
			slog.Any("impersonated_header_names", impersonatedHeaderNames(outbound)))

		handler.ServeHTTP(rw, reqctx.WithImpersonation(req, imp))
	})
}

// asAuthenticated returns the identity kube-apiserver would authorize an
// impersonation request for: its authenticator adds system:authenticated to
// every user it authenticates before the impersonation check runs, so an
// impersonate grant bound to that group works there. The SubjectAccessReviews
// ask about the same identity, so the grant works through the proxy too.
// inbound itself is left untouched; it is still what the access record and the
// originaluser extras report.
func asAuthenticated(inbound authuser.Info) authuser.Info {
	return &authuser.DefaultInfo{
		Name:   inbound.GetName(),
		UID:    inbound.GetUID(),
		Groups: authenticatedGroups(inbound.GetGroups()),
		Extra:  inbound.GetExtra(),
	}
}

// authenticatedGroups returns a copy of groups that includes
// system:authenticated, added only if absent. It copies because user.Info
// implementations are not required to return fresh slices, so appending to
// GetGroups() in place could mutate cached or shared authenticator state.
func authenticatedGroups(groups []string) []string {
	out := slices.Clone(groups)
	if !slices.Contains(out, authuser.AllAuthenticated) {
		out = append(out, authuser.AllAuthenticated)
	}
	return out
}

// outboundIdentity builds the identity the API server is asked to impersonate
// for a request authenticated as inbound: target when the client impersonated
// someone (and the SubjectAccessReviews allowed it), inbound itself otherwise.
// The identity is enriched with the system:authenticated group, the client IP
// and configured extras, and, when impersonating, with the original identity
// so the API server's audit log records who really acted.
func (p *Proxy) outboundIdentity(req *http.Request, inbound, target authuser.Info) (*transport.ImpersonationConfig, error) {
	forwarded := inbound
	if target != nil {
		forwarded = target
	}

	// Both collections are copies: writing into GetExtra() could otherwise
	// mutate cached or shared authenticator state.
	groups := authenticatedGroups(forwarded.GetGroups())
	extra := cloneExtra(forwarded.GetExtra())

	if p.config.ExtraUserHeadersClientIPEnabled {
		extra[reqctx.UserHeaderClientIPKey] = append(extra[reqctx.UserHeaderClientIPKey], reqctx.ClientIP(req))
	}

	// append copies into the freshly cloned value slice, so the configured
	// slice is never aliased into the outbound request.
	for k, vs := range p.config.ExtraUserHeaders {
		extra[k] = append(extra[k], vs...)
	}

	if target != nil {
		extra[reqctx.ExtraKeyOriginalUser] = []string{inbound.GetName()}

		if origGroups := inbound.GetGroups(); len(origGroups) > 0 {
			extra[reqctx.ExtraKeyOriginalGroups] = slices.Clone(origGroups)
		}

		if inbound.GetUID() != "" {
			extra[reqctx.ExtraKeyOriginalUID] = []string{inbound.GetUID()}
		}

		if len(inbound.GetExtra()) > 0 {
			jsonExtras, err := json.Marshal(inbound.GetExtra())
			if err != nil {
				return nil, err
			}
			extra[reqctx.ExtraKeyOriginalExtra] = []string{string(jsonExtras)}
		}
	}

	return &transport.ImpersonationConfig{
		UserName: forwarded.GetName(),
		UID:      forwarded.GetUID(),
		Groups:   groups,
		Extra:    extra,
	}, nil
}

// impersonatedHeaderNames returns the sorted names of the impersonation headers
// the round tripper will send for this configuration. Names only: the values
// carry the impersonated identity, the client address and operator-supplied
// secrets, none of which belong in a log record. Sorted because map iteration
// is unordered and a record whose fields shuffle between otherwise identical
// requests is harder to diff.
func impersonatedHeaderNames(c *transport.ImpersonationConfig) []string {
	names := []string{transport.ImpersonateUserHeader}
	if len(c.Groups) > 0 {
		names = append(names, transport.ImpersonateGroupHeader)
	}
	if c.UID != "" {
		names = append(names, transport.ImpersonateUIDHeader)
	}
	for k := range c.Extra {
		names = append(names, transport.ImpersonateUserExtraHeaderPrefix+logging.Sanitize(k))
	}

	slices.Sort(names)

	return names
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
