// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// IssuerHolder carries the name of the issuer that accepted a token back out
// of the authenticator. authenticator.Token is handed a context and returns a
// *authenticator.Response, so it has no way to name itself on the request:
// writing the name into Response.User.Extra would be the only alternative, and
// that map becomes Impersonate-Extra- headers on the outbound request. The
// holder keeps issuer attribution a logging concern.
//
// A holder belongs to exactly one in-flight request. The router runs at most
// one issuer for a token, so the router writes each field at most one time.
type IssuerHolder struct {
	name     string
	selected string
}

// Name returns the issuer recorded on the holder, or "" when no authenticator
// accepted the token.
func (h *IssuerHolder) Name() string {
	return h.name
}

// Selected returns the issuer that verified the token, or "" when no issuer
// ran. The wrapper records the issuer also when that issuer refused the token.
func (h *IssuerHolder) Selected() string {
	return h.selected
}

// issuerHolderKey is the context key the holder travels under.
type issuerHolderKey struct{}

// WithIssuerHolder returns a context carrying a fresh holder for the
// authenticator to name itself on, and the holder to read back afterwards.
func WithIssuerHolder(ctx context.Context) (context.Context, *IssuerHolder) {
	holder := new(IssuerHolder)
	return context.WithValue(ctx, issuerHolderKey{}, holder), holder
}

// recordIssuer records the issuer that accepted the token on the holder the
// context carries. A context without one is not an error: the readiness probe
// drives the same authenticators with a fake JWT outside any request, and
// there is nothing there to attribute.
func recordIssuer(ctx context.Context, name string) {
	if holder, ok := ctx.Value(issuerHolderKey{}).(*IssuerHolder); ok {
		holder.name = name
	}
}

// recordSelected records the issuer that verified the token on the holder
// the context carries, whatever the result of the verification.
func recordSelected(ctx context.Context, name string) {
	if holder, ok := ctx.Value(issuerHolderKey{}).(*IssuerHolder); ok {
		holder.selected = name
	}
}

// AttributeToIssuer returns inner wrapped so that a token it accepts is
// attributed to name, the issuer's name as IssuerName derives it: the host of
// its URL, never the full URL. Wrap every per-issuer authenticator before
// they are combined into a union, so the record names the issuer that actually
// accepted the token rather than the set that was tried.
func AttributeToIssuer(name string, inner authenticator.Token) authenticator.Token {
	return &namedIssuer{name: name, inner: inner}
}

type namedIssuer struct {
	name  string
	inner authenticator.Token
}

// AuthenticateToken names this issuer on the request's holder when, and only
// when, it accepted the token. A refusal, or an acceptance reported alongside
// an error, attributes nothing: the request was not authenticated by this
// issuer.
func (n *namedIssuer) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	recordSelected(ctx, n.name)
	resp, ok, err := n.inner.AuthenticateToken(ctx, token)
	if ok && err == nil {
		recordIssuer(ctx, n.name)
	}
	return resp, ok, err
}
