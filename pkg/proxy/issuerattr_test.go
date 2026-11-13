// Copyright Jetstack Ltd. See LICENSE for details.
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/request/bearertoken"
	authuser "k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/transport"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/reqctx"
)

// leakProbeIssuerName is deliberately distinctive: the assertions below scan
// every impersonation key, header name and header value for it, and a name
// like "corp" could plausibly occur in one by accident.
const leakProbeIssuerName = "corp.example.test"

// capturingRT records the request the impersonating round tripper produced, so
// a test can assert on the headers that actually go to the API server rather
// than on the inbound ones.
type capturingRT struct {
	req *http.Request
}

func (c *capturingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.req = req
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header)}, nil
}

// TestIssuerNameNeverReachesImpersonationHeaders is the brief's primary
// security guarantee: the issuer that authenticated a request is named on
// records, and never on the identity the API server is asked to impersonate.
//
// It asserts at both points the name could leak. The impersonation config the
// handler builds is the source, and the headers the impersonating round
// tripper generates from it are what leaves the process: inspecting the
// inbound request headers instead would assert nothing at all, because the
// Impersonate-* headers do not exist until RoundTrip builds them.
//
// The authenticator is wrapped exactly as run.go wraps it, so the whole path
// under test is the production one — a wrapper that put the name into
// Response.User.Extra would fail both halves.
func TestIssuerNameNeverReachesImpersonationHeaders(t *testing.T) {
	p := newTestProxy(t)
	p.oidcRequestAuthenticator = bearertoken.New(authn.AttributeToIssuer(leakProbeIssuerName, p.fakeToken))

	// An identity extra and the client-IP extra guarantee the round tripper
	// really builds Impersonate-Extra- headers, so the scan below has
	// something to scan and cannot pass vacuously.
	p.config.ExtraUserHeadersClientIPEnabled = true
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").Return(
		&authenticator.Response{
			User: &authuser.DefaultInfo{
				Name:   "alice",
				UID:    "uid-1",
				Groups: []string{"devs"},
				Extra:  map[string][]string{"foo": {"x"}},
			},
		}, true, nil)

	capture := new(capturingRT)
	p.clientTransport = capture

	var served bool
	chain := p.withAuthenticateRequest(p.withImpersonateRequest(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		served = true

		conf := reqctx.ImpersonationConfig(req)
		if conf == nil {
			t.Fatal("no impersonation config on an authenticated request")
		}
		for k, vs := range conf.ImpersonationConfig.Extra {
			if mentionsIssuer(k) {
				t.Errorf("issuer leaked into impersonation extra key %q", k)
			}
			for _, v := range vs {
				if mentionsIssuer(v) {
					t.Errorf("issuer leaked into impersonation extra %q = %q", k, v)
				}
			}
		}

		if _, err := p.RoundTrip(req); err != nil {
			t.Fatalf("RoundTrip: %s", err)
		}
	})))

	chain.ServeHTTP(httptest.NewRecorder(), reservedIdentityRequest(t, nil))

	if !served {
		t.Fatal("the authenticated request never reached impersonation")
	}
	if capture.req == nil {
		t.Fatal("no request reached the client transport")
	}

	var impersonateExtras int
	for k, vs := range capture.req.Header {
		if strings.HasPrefix(k, transport.ImpersonateUserExtraHeaderPrefix) {
			impersonateExtras++
		}
		if mentionsIssuer(k) {
			t.Errorf("issuer leaked into outbound header name %q", k)
		}
		for _, v := range vs {
			if mentionsIssuer(v) {
				t.Errorf("issuer leaked into outbound header %s: %q", k, v)
			}
		}
	}

	// Without generated impersonation headers the scan above would prove
	// nothing, which is exactly how the previous version of this test passed.
	if impersonateExtras == 0 {
		t.Fatal("the round tripper generated no Impersonate-Extra- headers, so the scan asserts nothing")
	}
	if got := capture.req.Header.Get(transport.ImpersonateUserHeader); got != "alice" {
		t.Errorf("outbound %s = %q, want alice", transport.ImpersonateUserHeader, got)
	}

	// The name is reported — on the record, which is the only place it belongs.
	if got := p.logs.Only(t, logging.EventAuthnOIDCSucceeded).String("issuer_name"); got != leakProbeIssuerName {
		t.Errorf("issuer_name = %q, want %q", got, leakProbeIssuerName)
	}
}

// mentionsIssuer reports whether a key, header name or value names the issuer
// that authenticated the request, or claims to carry issuer information at
// all. Case-insensitive: header names are canonicalized on the way out.
func mentionsIssuer(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, leakProbeIssuerName) || strings.Contains(s, "issuer")
}

// TestWithAuthenticateRequestPublishesIssuerName pins the read-back: the name
// the wrapper stored on the holder is on the request context by the time the
// next handler — and with it every access record — runs.
func TestWithAuthenticateRequestPublishesIssuerName(t *testing.T) {
	p := newTestProxy(t)
	p.fakeToken.EXPECT().AuthenticateToken(gomock.Any(), "fake-token").DoAndReturn(
		func(ctx context.Context, _ string) (*authenticator.Response, bool, error) {
			authn.RecordIssuer(ctx, testIssuerName)
			return &authenticator.Response{User: &authuser.DefaultInfo{Name: "alice"}}, true, nil
		})

	var got string
	p.withAuthenticateRequest(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		got = reqctx.IssuerName(req)
	})).ServeHTTP(httptest.NewRecorder(), reservedIdentityRequest(t, nil))

	if got != testIssuerName {
		t.Fatalf("issuer name on the request context = %q, want %q", got, testIssuerName)
	}
}
