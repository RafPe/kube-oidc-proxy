// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiserver "k8s.io/apiserver/pkg/apis/apiserver"
	apiserverv1 "k8s.io/apiserver/pkg/apis/apiserver/v1"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"

	"github.com/rafpe/kube-oidc-proxy/pkg/authn/v1alpha1"
)

// configCase is one LoadConfiguration case. doc is the Go value of the
// document. edit, when set, changes the generic map form of doc before the
// test writes it. raw, when set, is the document text and replaces doc.
type configCase struct {
	name    string
	doc     any
	edit    func(m map[string]any)
	raw     func(t *testing.T) []byte
	wantErr []string // substrings; empty means expect success
	want    *Configuration
}

func (tc configCase) data(t *testing.T) []byte {
	t.Helper()
	switch {
	case tc.raw != nil:
		return tc.raw(t)
	case tc.edit != nil:
		return editDoc(t, tc.doc, tc.edit)
	default:
		return marshalDoc(t, tc.doc)
	}
}

func runConfigCases(t *testing.T, tests []configCase) {
	t.Helper()
	compiler := authenticationcel.NewDefaultCompiler()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfiguration(writeDoc(t, tc.data(t)), compiler)

			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("expected an error containing %q, got: %v", want, err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, cfg); diff != "" {
				t.Fatalf("LoadConfiguration() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// celJWT returns a v1 JWT authenticator with a CEL groups mapping and a claim
// validation rule.
func celJWT() apiserverv1.JWTAuthenticator {
	jwt := testJWT("https://issuer1.example.com", "one:", "aud-one")
	jwt.ClaimMappings.Groups = apiserverv1.PrefixedClaimOrExpression{Expression: `["g:" + claims.owner]`}
	jwt.ClaimValidationRules = []apiserverv1.ClaimValidationRule{
		{Expression: `claims.owner == "my-org"`, Message: "only my-org"},
	}
	return jwt
}

// wantCELJWT returns the internal form of celJWT.
func wantCELJWT() apiserver.JWTAuthenticator {
	jwt := wantJWT("https://issuer1.example.com", "one:", "aud-one")
	jwt.ClaimMappings.Groups = apiserver.PrefixedClaimOrExpression{Expression: `["g:" + claims.owner]`}
	jwt.ClaimValidationRules = []apiserver.ClaimValidationRule{
		{Expression: `claims.owner == "my-org"`, Message: "only my-org"},
	}
	return jwt
}

// v1beta1Doc returns an apiserver.config.k8s.io/v1beta1 document with one
// issuer. It maps the sub claim to the username with the prefix "one:".
func v1beta1Doc(policy apiserverv1beta1.AudienceMatchPolicyType, audiences ...string) apiserverv1beta1.AuthenticationConfiguration {
	prefix := "one:"
	return apiserverv1beta1.AuthenticationConfiguration{
		TypeMeta: metav1.TypeMeta{APIVersion: apiserverv1beta1.ConfigSchemeGroupVersion.String(), Kind: v1alpha1.Kind},
		JWT: []apiserverv1beta1.JWTAuthenticator{{
			Issuer: apiserverv1beta1.Issuer{
				URL:                 "https://issuer1.example.com",
				Audiences:           audiences,
				AudienceMatchPolicy: policy,
			},
			ClaimMappings: apiserverv1beta1.ClaimMappings{
				Username: apiserverv1beta1.PrefixedClaimOrExpression{Claim: "sub", Prefix: &prefix},
			},
		}},
	}
}

// withPolicy returns jwt with audienceMatchPolicy set to policy.
func withPolicy(jwt apiserverv1.JWTAuthenticator, policy apiserverv1.AudienceMatchPolicyType) apiserverv1.JWTAuthenticator {
	jwt.Issuer.AudienceMatchPolicy = policy
	return jwt
}

func TestAuthenticationConfigLoad(t *testing.T) {
	singleMatchAny := wantJWT("https://issuer1.example.com", "one:", "aud-one")
	singleMatchAny.Issuer.AudienceMatchPolicy = apiserver.AudienceMatchPolicyMatchAny

	runConfigCases(t, []configCase{
		{
			name: "valid v1 with CEL mappings and validation rules",
			doc:  upstreamDoc(celJWT(), testJWT("https://issuer2.example.com", "two:", "aud-two")),
			want: &Configuration{Entries: []Entry{
				{Name: "issuer1.example.com", JWT: wantCELJWT()},
				{Name: "issuer2.example.com", JWT: wantJWT("https://issuer2.example.com", "two:", "aud-two")},
			}},
		},
		{
			name: "valid v1beta1",
			doc:  v1beta1Doc("", "aud-one"),
			want: &Configuration{Entries: []Entry{
				{Name: "issuer1.example.com", JWT: wantJWT("https://issuer1.example.com", "one:", "aud-one")},
			}},
		},
		{
			name: "wrong kind rejected",
			doc:  upstreamDoc(),
			edit: func(m map[string]any) {
				m["kind"] = "AuthorizationConfiguration"
				delete(m, "jwt")
				m["authorizers"] = []any{}
			},
			wantErr: []string{"expected AuthenticationConfiguration"},
		},
		{
			name: "unknown field rejected (strict decoding)",
			doc:  upstreamDoc(testJWT("https://issuer1.example.com", "one:", "aud-one")),
			edit: func(m map[string]any) {
				issuer := m["jwt"].([]any)[0].(map[string]any)["issuer"].(map[string]any)
				issuer["audiencess"] = []any{"typo"}
			},
			wantErr: []string{"unknown field"},
		},
		{
			name: "duplicate issuer URLs rejected",
			doc: upstreamDoc(
				testJWT("https://issuer1.example.com", "one:", "aud-one"),
				testJWT("https://issuer1.example.com", "two:", "aud-two")),
			wantErr: []string{"Duplicate value"},
		},
		{
			name: "invalid CEL expression rejected",
			doc: upstreamDoc(apiserverv1.JWTAuthenticator{
				Issuer: apiserverv1.Issuer{URL: "https://issuer1.example.com", Audiences: []string{"aud-one"}},
				ClaimMappings: apiserverv1.ClaimMappings{
					Username: apiserverv1.PrefixedClaimOrExpression{Expression: "claims."},
				},
			}),
			wantErr: []string{"compilation failed"},
		},
		{
			name: "anonymous section rejected",
			doc: func() apiserverv1.AuthenticationConfiguration {
				doc := upstreamDoc(testJWT("https://issuer1.example.com", "one:", "aud-one"))
				doc.Anonymous = &apiserverv1.AnonymousAuthConfig{Enabled: true}
				return doc
			}(),
			wantErr: []string{"not supported"},
		},
		{
			name:    "empty jwt list rejected",
			doc:     upstreamDoc(),
			wantErr: []string{"must not be empty"},
		},
		{
			name: "multiple audiences accepted with audienceMatchPolicy MatchAny",
			doc:  upstreamDoc(testJWT("https://issuer1.example.com", "one:", "aud-one", "aud-two")),
			want: &Configuration{Entries: []Entry{
				{Name: "issuer1.example.com", JWT: wantJWT("https://issuer1.example.com", "one:", "aud-one", "aud-two")},
			}},
		},
		{
			name: "multiple audiences accepted with MatchAny in v1beta1",
			doc:  v1beta1Doc(apiserverv1beta1.AudienceMatchPolicyMatchAny, "aud-one", "aud-two"),
			want: &Configuration{Entries: []Entry{
				{Name: "issuer1.example.com", JWT: wantJWT("https://issuer1.example.com", "one:", "aud-one", "aud-two")},
			}},
		},
		{
			name: "single audience accepted with explicit MatchAny",
			doc: upstreamDoc(withPolicy(testJWT("https://issuer1.example.com", "one:", "aud-one"),
				apiserverv1.AudienceMatchPolicyMatchAny)),
			want: &Configuration{Entries: []Entry{{Name: "issuer1.example.com", JWT: singleMatchAny}}},
		},
		{
			name: "multiple audiences rejected without audienceMatchPolicy",
			doc: upstreamDoc(withPolicy(testJWT("https://issuer1.example.com", "one:", "aud-one", "aud-two"),
				"")),
			wantErr: []string{"audienceMatchPolicy must be MatchAny for multiple audiences"},
		},
		{
			name: "unknown audienceMatchPolicy rejected",
			doc: upstreamDoc(withPolicy(testJWT("https://issuer1.example.com", "one:", "aud-one", "aud-two"),
				"MatchAll")),
			wantErr: []string{"audienceMatchPolicy"},
		},
		{
			name:    "duplicate audiences within one issuer rejected",
			doc:     upstreamDoc(testJWT("https://issuer1.example.com", "one:", "aud-one", "aud-one")),
			wantErr: []string{"Duplicate value"},
		},
	})
}

func TestAuthenticationConfigLoadMissingFile(t *testing.T) {
	if _, err := LoadConfiguration("/does/not/exist.yaml", authenticationcel.NewDefaultCompiler()); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

const (
	gkeVendorURL   = "https://container.googleapis.com/v1/projects/vendor/locations/europe-west1/clusters/a"
	gkeInternalURL = "https://container.googleapis.com/v1/projects/internal/locations/europe-west1/clusters/b"
	ghaURL         = "https://token.actions.githubusercontent.com"
)

// gkeProxyDoc returns a document of the proxy kind with two GKE cluster
// issuers on one host.
func gkeProxyDoc() v1alpha1.AuthenticationConfiguration {
	return proxyDoc(
		proxyIssuer("gke-vendor", gkeVendorURL, "aud-vendor"),
		proxyIssuer("gke-internal", gkeInternalURL, "aud-internal"))
}

// withDiscoveryURL returns iss with the discovery URL set to url.
func withDiscoveryURL(iss v1alpha1.Issuer, url string) v1alpha1.Issuer {
	iss.JWT.Issuer.DiscoveryURL = &url
	return iss
}

func TestProxyAuthenticationConfigLoad(t *testing.T) {
	tooMany := make([]v1alpha1.Issuer, maxIssuers+1)
	for i := range tooMany {
		tooMany[i] = proxyIssuer(fmt.Sprintf("issuer-%d", i), fmt.Sprintf("https://issuer-%d.example.com", i), "aud")
	}
	badCEL := proxyIssuer("b", "https://b.example.com", "aud")
	badCEL.JWT.ClaimMappings.Username = apiserverv1.PrefixedClaimOrExpression{Expression: "claims.sub +"}
	const discovery = "https://discovery.example.com/.well-known/openid-configuration"

	runConfigCases(t, []configCase{
		{
			name: "issuers on one host get the configured names",
			doc:  gkeProxyDoc(),
			want: &Configuration{ProxyKind: true, Entries: []Entry{
				wantProxyEntry("gke-vendor", gkeVendorURL, "aud-vendor"),
				wantProxyEntry("gke-internal", gkeInternalURL, "aud-internal"),
			}},
		},
		{
			name: "one issuer URL with disjoint audiences loads",
			doc: proxyDoc(
				proxyIssuer("gha-int", ghaURL, "aud-int"),
				proxyIssuer("gha-vendor", ghaURL, "aud-vendor")),
			want: &Configuration{ProxyKind: true, Entries: []Entry{
				wantProxyEntry("gha-int", ghaURL, "aud-int"),
				wantProxyEntry("gha-vendor", ghaURL, "aud-vendor"),
			}},
		},
		{
			name: "every field of an entry is kept",
			doc:  proxyDoc(v1alpha1.Issuer{Name: "cel", JWT: celJWT()}),
			want: &Configuration{ProxyKind: true, Entries: []Entry{{Name: "cel", JWT: wantCELJWT()}}},
		},
		{
			name: "a name can contain dots",
			doc:  proxyDoc(proxyIssuer("idp.example.com", "https://idp.example.com", "aud")),
			want: &Configuration{ProxyKind: true, Entries: []Entry{
				wantProxyEntry("idp.example.com", "https://idp.example.com", "aud"),
			}},
		},
		{
			name: "one issuer URL with a shared audience is refused",
			doc: proxyDoc(
				proxyIssuer("gha-int", ghaURL, "aud-int", "aud-shared"),
				proxyIssuer("gha-vendor", ghaURL, "aud-shared")),
			wantErr: []string{"issuers[0]", "issuers[1]", `"aud-shared"`},
		},
		{
			name: "a shared audience on different issuer URLs loads",
			doc: proxyDoc(
				proxyIssuer("a", "https://a.example.com", "aud"),
				proxyIssuer("b", "https://b.example.com", "aud")),
			want: &Configuration{ProxyKind: true, Entries: []Entry{
				wantProxyEntry("a", "https://a.example.com", "aud"),
				wantProxyEntry("b", "https://b.example.com", "aud"),
			}},
		},
		{
			name: "duplicate names are refused",
			doc: proxyDoc(
				proxyIssuer("corp", "https://a.example.com", "aud"),
				proxyIssuer("corp", "https://b.example.com", "aud")),
			wantErr: []string{"issuers[0]", "issuers[1]", `"corp"`},
		},
		{
			name:    "a name that is not a DNS-1123 subdomain is refused",
			doc:     proxyDoc(proxyIssuer("Corp_A", "https://a.example.com", "aud")),
			wantErr: []string{"issuers[0].name"},
		},
		{
			name:    "a missing name is refused",
			doc:     proxyDoc(proxyIssuer("", "https://a.example.com", "aud")),
			wantErr: []string{"issuers[0].name"},
		},
		{
			name: "the same discoveryURL is refused",
			doc: proxyDoc(
				withDiscoveryURL(proxyIssuer("a", "https://a.example.com", "aud"), discovery),
				withDiscoveryURL(proxyIssuer("b", "https://b.example.com", "aud"), discovery)),
			wantErr: []string{"issuers[0]", "issuers[1]", "discoveryURL"},
		},
		{
			name:    "an entry that fails upstream validation is refused by index",
			doc:     proxyDoc(proxyIssuer("a", "https://a.example.com", "aud"), badCEL),
			wantErr: []string{"issuers[1]"},
		},
		{
			name:    "more issuers than the limit are refused",
			doc:     proxyDoc(tooMany...),
			wantErr: []string{fmt.Sprintf("the limit is %d", maxIssuers)},
		},
		{
			name:    "an unknown field is refused",
			doc:     proxyDoc(proxyIssuer("a", "https://a.example.com", "aud")),
			edit:    func(m map[string]any) { m["extra"] = true },
			wantErr: []string{"unknown field"},
		},
		{
			name: "an unknown field inside jwt is refused",
			doc:  proxyDoc(proxyIssuer("a", "https://a.example.com", "aud")),
			edit: func(m map[string]any) {
				firstJWT(m)["issuer"].(map[string]any)["audiencess"] = []any{"typo"}
			},
			wantErr: []string{"unknown field"},
		},
		{
			name: "a key with the wrong case inside jwt is refused, as upstream refuses it",
			doc:  proxyDoc(proxyIssuer("a", "https://a.example.com", "aud")),
			edit: func(m map[string]any) {
				issuer := firstJWT(m)["issuer"].(map[string]any)
				issuer["Audiences"] = issuer["audiences"]
				delete(issuer, "audiences")
			},
			wantErr: []string{"unknown field"},
		},
		{
			name:    "a key with the wrong case at the top is refused",
			doc:     proxyDoc(proxyIssuer("a", "https://a.example.com", "aud")),
			edit:    func(m map[string]any) { m["Issuers"] = []any{} },
			wantErr: []string{"unknown field"},
		},
		{
			// A Go map cannot hold a duplicate key, so the test adds the
			// second key to the marshaled text.
			name: "a duplicate key is refused",
			raw: func(t *testing.T) []byte {
				data := string(marshalDoc(t, proxyDoc(proxyIssuer("a", "https://a.example.com", "aud"))))
				if !strings.Contains(data, "\n  name: a\n") {
					t.Fatalf("the marshaled document has no name key to duplicate:\n%s", data)
				}
				return []byte(strings.Replace(data, "\n  name: a\n", "\n  name: a\n  name: b\n", 1))
			},
			wantErr: []string{`"name" already set`},
		},
		{
			name:    "an empty issuers list is refused",
			doc:     proxyDoc(),
			wantErr: []string{"issuers list must not be empty"},
		},
		{
			name:    "a different kind is refused",
			doc:     proxyDoc(),
			edit:    func(m map[string]any) { m["kind"] = "AuthorizationConfiguration" },
			wantErr: []string{"expected AuthenticationConfiguration"},
		},
	})
}
