// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/authenticator"
	tokenunion "k8s.io/apiserver/pkg/authentication/token/union"
	"k8s.io/apiserver/pkg/authentication/user"
)

// fakeIssuer behaves as the upstream JWT authenticator of one issuer. For a
// token whose iss is not its URL, it returns ok false and no error. For other
// tokens, it returns result. It counts the tokens it verifies.
type fakeIssuer struct {
	url    string
	result error
	calls  int
}

func (f *fakeIssuer) AuthenticateToken(_ context.Context, token string) (*authenticator.Response, bool, error) {
	claims, err := parseUntrustedClaims(token)
	if err != nil || claims.issuer != f.url {
		return nil, false, nil
	}
	f.calls++
	if f.result != nil {
		return nil, false, f.result
	}
	return &authenticator.Response{User: &user.DefaultInfo{Name: f.url}}, true, nil
}

// testToken returns a compact JWT with payload as its claims and a fake
// signature.
func testToken(t *testing.T, payload any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(raw) + ".c2ln"
}

// TestRouterMatchesUnionForUniqueIssuerURLs pins that the router gives the
// same answer as the upstream fail-on-error union when every issuer URL is
// unique. The issuer URLs of the upstream kind are always unique.
func TestRouterMatchesUnionForUniqueIssuerURLs(t *testing.T) {
	verifyErr := errors.New("oidc: verify token: audience mismatch")

	tokens := map[string]string{
		"not a JWT":            "not-a-jwt",
		"JSON instead of JWT":  `{"iss":"https://a.example.com"}`,
		"undecodable payload":  "e30.%%%.c2ln",
		"iss is not a string":  testToken(t, map[string]any{"iss": 42}),
		"unknown iss":          testToken(t, map[string]any{"iss": "https://unknown.example.com"}),
		"legacy Google iss":    testToken(t, map[string]any{"iss": "accounts.google.com", "aud": "x"}),
		"string aud":           testToken(t, map[string]any{"iss": "https://a.example.com", "aud": "aud-a"}),
		"array aud":            testToken(t, map[string]any{"iss": "https://b.example.com", "aud": []string{"aud-b", "other"}}),
		"numeric aud":          testToken(t, map[string]any{"iss": "https://a.example.com", "aud": 7}),
		"missing aud":          testToken(t, map[string]any{"iss": "https://b.example.com"}),
		"aud of other issuer":  testToken(t, map[string]any{"iss": "https://a.example.com", "aud": "aud-b"}),
		"failing verification": testToken(t, map[string]any{"iss": "https://c.example.com", "aud": "aud-c"}),
	}

	newIssuers := func() []*fakeIssuer {
		return []*fakeIssuer{
			{url: "https://a.example.com"},
			{url: "https://b.example.com"},
			{url: "https://c.example.com", result: verifyErr},
			{url: "https://accounts.google.com"},
		}
	}
	audiences := [][]string{{"aud-a"}, {"aud-b"}, {"aud-c"}, {"aud-g"}}

	for name, token := range tokens {
		t.Run(name, func(t *testing.T) {
			unionIssuers, routerIssuers := newIssuers(), newIssuers()

			unionMembers := make([]authenticator.Token, 0, len(unionIssuers))
			for _, f := range unionIssuers {
				unionMembers = append(unionMembers, f)
			}
			routes := make([]route, 0, len(routerIssuers))
			for i, f := range routerIssuers {
				routes = append(routes, route{url: f.url, audiences: audiences[i], authenticator: f})
			}

			_, wantOK, wantErr := tokenunion.NewFailOnError(unionMembers...).AuthenticateToken(context.Background(), token)
			_, gotOK, gotErr := newRouter(routes).AuthenticateToken(context.Background(), token)

			if gotOK != wantOK || (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("router = (ok=%v, err=%v), union = (ok=%v, err=%v)", gotOK, gotErr, wantOK, wantErr)
			}
			if wantErr != nil && !errors.Is(gotErr, wantErr) {
				t.Fatalf("router error = %v, want the issuer error %v unchanged", gotErr, wantErr)
			}
			for i := range unionIssuers {
				if routerIssuers[i].calls != unionIssuers[i].calls {
					t.Fatalf("issuer %s verified %d tokens through the router, %d through the union",
						routerIssuers[i].url, routerIssuers[i].calls, unionIssuers[i].calls)
				}
			}
		})
	}
}

// TestRouterSelectsAnIssuerByAudience pins the routing between issuers that
// share an issuer URL.
func TestRouterSelectsAnIssuerByAudience(t *testing.T) {
	const shared = "https://token.actions.githubusercontent.com"
	verifyErr := errors.New("oidc: error evaluating claim validation expression")

	tests := []struct {
		name       string
		claims     map[string]any
		wantOK     bool
		wantErr    error
		wantCalled string // name of the only issuer that verifies; empty for none
	}{
		{name: "string aud selects its issuer", claims: map[string]any{"iss": shared, "aud": "aud-int"}, wantOK: true, wantCalled: "int"},
		{name: "array aud selects its issuer", claims: map[string]any{"iss": shared, "aud": []string{"unrelated", "aud-vendor"}}, wantErr: verifyErr, wantCalled: "vendor"},
		{name: "aud of no issuer is unrouted", claims: map[string]any{"iss": shared, "aud": "aud-other"}, wantErr: ErrAudienceUnrouted},
		{name: "aud of two issuers is unrouted", claims: map[string]any{"iss": shared, "aud": []string{"aud-int", "aud-vendor"}}, wantErr: ErrAudienceUnrouted},
		{name: "missing aud is unrouted", claims: map[string]any{"iss": shared}, wantErr: ErrAudienceUnrouted},
		{name: "numeric aud is unrouted", claims: map[string]any{"iss": shared, "aud": 7}, wantErr: ErrAudienceUnrouted},
		{name: "other iss is not claimed", claims: map[string]any{"iss": "https://other.example.com", "aud": "aud-int"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuers := map[string]*fakeIssuer{
				"int":    {url: shared},
				"vendor": {url: shared, result: verifyErr},
			}
			r := newRouter([]route{
				{url: shared, audiences: []string{"aud-int", "aud-int-2"}, authenticator: issuers["int"]},
				{url: shared, audiences: []string{"aud-vendor"}, authenticator: issuers["vendor"]},
			})

			_, ok, err := r.AuthenticateToken(context.Background(), testToken(t, tc.claims))

			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (err %v)", ok, tc.wantOK, err)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			for name, f := range issuers {
				want := 0
				if name == tc.wantCalled {
					want = 1
				}
				if f.calls != want {
					t.Fatalf("issuer %s verified %d tokens, want %d", name, f.calls, want)
				}
			}
		})
	}
}

// TestErrAudienceUnroutedText pins that the routing error contains no token
// content and does not read as an uninitialized issuer to the readiness
// probe.
func TestErrAudienceUnroutedText(t *testing.T) {
	msg := ErrAudienceUnrouted.Error()
	if strings.Contains(msg, "not initialized") {
		t.Fatalf("ErrAudienceUnrouted = %q, must not contain %q", msg, "not initialized")
	}
	for _, forbidden := range []string{"http", "aud-"} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("ErrAudienceUnrouted = %q, must not contain %q", msg, forbidden)
		}
	}
}
