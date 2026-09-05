// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"

	"k8s.io/apiserver/pkg/authentication/authenticator"
)

// issuerHolder carries the name of the issuer that accepted a token back out
// of the authenticator. authenticator.Token is handed a context and returns a
// *authenticator.Response, so it has no way to name itself on the request:
// writing the name into Response.User.Extra would be the only alternative, and
// that map becomes Impersonate-Extra- headers on the outbound request. The
// holder keeps issuer attribution a logging concern.
//
// A holder belongs to exactly one in-flight request and is written at most
// once, by the single authenticator that accepted the token: the union
// authenticator tries its members in sequence, and the ones that refuse the
// token never reach the wrapper's success path.
type issuerHolder struct {
	name string
}

// issuerHolderKey is the proxy-private context key the holder travels under.
type issuerHolderKey struct{}

// withIssuerHolder returns a context carrying a fresh holder for the
// authenticator to name itself on, and the holder to read back afterwards.
func withIssuerHolder(ctx context.Context) (context.Context, *issuerHolder) {
	holder := new(issuerHolder)
	return context.WithValue(ctx, issuerHolderKey{}, holder), holder
}

// setIssuerName records the issuer that accepted the token on the holder the
// context carries. A context without one is not an error: the readiness probe
// drives the same authenticators with a fake JWT outside any request, and
// there is nothing there to attribute.
func setIssuerName(ctx context.Context, name string) {
	if holder, ok := ctx.Value(issuerHolderKey{}).(*issuerHolder); ok {
		holder.name = name
	}
}

// WithIssuerName returns inner wrapped so that a token it accepts is
// attributed to name, which is the issuer's configured name or the host of its
// URL — never the full issuer URL. Wrap every per-issuer authenticator before
// they are combined into a union, so the record names the issuer that actually
// accepted the token rather than the set that was tried.
func WithIssuerName(name string, inner authenticator.Token) authenticator.Token {
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
	resp, ok, err := n.inner.AuthenticateToken(ctx, token)
	if ok && err == nil {
		setIssuerName(ctx, n.name)
	}
	return resp, ok, err
}
