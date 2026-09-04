// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authuser "k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/mocks"
	proxycontext "github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

// TestIssuerNameNeverReachesImpersonationHeaders is the property that keeps
// issuer attribution a logging concern: the name of the issuer that accepted
// the token reaches the records, and never the identity the API server is
// asked to impersonate.
func TestIssuerNameNeverReachesImpersonationHeaders(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		func(ctx context.Context, _ string) (*authenticator.Response, bool, error) {
			setIssuerName(ctx, "corp") // helper the wrapper uses
			return &authenticator.Response{User: &authuser.DefaultInfo{Name: "alice"}}, true, nil
		})
	var outbound http.Header
	chain := p.withAuthenticateRequest(p.withImpersonateRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outbound = r.Header
	})))
	req := reservedIdentityRequest(t, nil)
	req = req.WithContext(logging.NewContext(req.Context(), p.logger))
	chain.ServeHTTP(httptest.NewRecorder(), req)
	for k := range outbound {
		if strings.HasPrefix(strings.ToLower(k), "impersonate-extra-") && strings.Contains(strings.ToLower(k), "issuer") {
			t.Fatalf("issuer leaked into %s", k)
		}
	}
	if p.logs.Only(t, logging.EventAuthnOIDCSucceeded).String("issuer_name") != "corp" {
		t.Fatal("issuer_name missing from authn record")
	}
}

// TestWithIssuerNameAttributesOnlyAcceptedTokens pins what the wrapper reports.
// A rejected or errored token was not accepted by this issuer, so naming it
// would attribute a request to an issuer that refused it.
func TestWithIssuerNameAttributesOnlyAcceptedTokens(t *testing.T) {
	accepted := &authenticator.Response{User: &authuser.DefaultInfo{Name: "alice"}}

	tests := map[string]struct {
		resp *authenticator.Response
		ok   bool
		err  error
		want string
	}{
		"accepted token is attributed": {resp: accepted, ok: true, want: "corp"},
		"rejected token is not":        {},
		"errored token is not":         {err: errors.New("token is expired")},
		"error alongside ok is not":    {resp: accepted, ok: true, err: errors.New("token is expired")},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			inner := mocks.NewMockToken(ctrl)
			inner.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(test.resp, test.ok, test.err)

			ctx, holder := withIssuerHolder(context.Background())
			if _, _, err := WithIssuerName("corp", inner).AuthenticateToken(ctx, "fake-token"); !errors.Is(err, test.err) {
				t.Fatalf("AuthenticateToken error = %v, want %v", err, test.err)
			}

			if holder.name != test.want {
				t.Errorf("issuer name = %q, want %q", holder.name, test.want)
			}
		})
	}
}

// TestSetIssuerNameWithoutHolderIsNoOp covers the callers that authenticate a
// token outside the request chain — the readiness probe drives the same
// wrapped authenticator with a fake JWT — where no holder was ever placed on
// the context.
func TestSetIssuerNameWithoutHolderIsNoOp(t *testing.T) {
	setIssuerName(context.Background(), "corp")
}

// TestWithAuthenticateRequestPublishesIssuerName pins the read-back: the name
// the wrapper stored on the holder is on the request context by the time the
// next handler — and with it every access record — runs.
func TestWithAuthenticateRequestPublishesIssuerName(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		func(ctx context.Context, _ string) (*authenticator.Response, bool, error) {
			setIssuerName(ctx, testIssuerName)
			return &authenticator.Response{User: &authuser.DefaultInfo{Name: "alice"}}, true, nil
		})

	var got string
	p.withAuthenticateRequest(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = proxycontext.IssuerName(req)
	})).ServeHTTP(httptest.NewRecorder(), reservedIdentityRequest(t, nil))

	if got != testIssuerName {
		t.Fatalf("issuer name on the request context = %q, want %q", got, testIssuerName)
	}
}
