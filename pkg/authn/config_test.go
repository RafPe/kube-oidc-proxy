// Copyright Jetstack Ltd. See LICENSE for details.
package authn

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
)

func writeAuthConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validV1Config = `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
    groups:
      expression: '["g:" + claims.owner]'
  claimValidationRules:
  - expression: 'claims.owner == "my-org"'
    message: "only my-org"
- issuer:
    url: https://issuer2.example.com
    audiences: ["aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "two:"
`

const validV1Beta1Config = `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`

func TestAuthenticationConfigLoad(t *testing.T) {
	compiler := authenticationcel.NewDefaultCompiler()

	tests := []struct {
		name        string
		config      string
		wantErr     string // substring; empty means expect success
		wantIssuers int
	}{
		{
			name:        "valid v1 with CEL mappings and validation rules",
			config:      validV1Config,
			wantIssuers: 2,
		},
		{
			name:        "valid v1beta1",
			config:      validV1Beta1Config,
			wantIssuers: 1,
		},
		{
			name: "wrong kind rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers: []
`,
			wantErr: "expected AuthenticationConfiguration",
		},
		{
			name: "unknown field rejected (strict decoding)",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiencess: ["typo"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "unknown field",
		},
		{
			name: "duplicate issuer URLs rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "two:"
`,
			wantErr: "Duplicate value",
		},
		{
			name: "invalid CEL expression rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      expression: 'claims.'
`,
			wantErr: "compilation failed",
		},
		{
			name: "anonymous section rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
anonymous:
  enabled: true
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "not supported",
		},
		{
			name: "empty jwt list rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt: []
`,
			wantErr: "must not be empty",
		},
		{
			name: "multiple audiences accepted with audienceMatchPolicy MatchAny",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one", "aud-two"]
    audienceMatchPolicy: MatchAny
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantIssuers: 1,
		},
		{
			name: "multiple audiences accepted with MatchAny in v1beta1",
			config: `apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one", "aud-two"]
    audienceMatchPolicy: MatchAny
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantIssuers: 1,
		},
		{
			name: "single audience accepted with explicit MatchAny",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one"]
    audienceMatchPolicy: MatchAny
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantIssuers: 1,
		},
		{
			name: "multiple audiences rejected without audienceMatchPolicy",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one", "aud-two"]
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "audienceMatchPolicy must be MatchAny for multiple audiences",
		},
		{
			name: "unknown audienceMatchPolicy rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one", "aud-two"]
    audienceMatchPolicy: MatchAll
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "audienceMatchPolicy",
		},
		{
			name: "duplicate audiences within one issuer rejected",
			config: `apiVersion: apiserver.config.k8s.io/v1
kind: AuthenticationConfiguration
jwt:
- issuer:
    url: https://issuer1.example.com
    audiences: ["aud-one", "aud-one"]
    audienceMatchPolicy: MatchAny
  claimMappings:
    username:
      claim: sub
      prefix: "one:"
`,
			wantErr: "Duplicate value",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfiguration(writeAuthConfig(t, tc.config), compiler)

			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.Entries) != tc.wantIssuers {
				t.Fatalf("expected %d issuers, got %d", tc.wantIssuers, len(cfg.Entries))
			}
		})
	}
}

func TestAuthenticationConfigLoadMissingFile(t *testing.T) {
	if _, err := LoadConfiguration("/does/not/exist.yaml", authenticationcel.NewDefaultCompiler()); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

const validProxyConfig = `apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1
kind: AuthenticationConfiguration
issuers:
- name: gke-vendor
  jwt:
    issuer:
      url: https://container.googleapis.com/v1/projects/vendor/locations/europe-west1/clusters/a
      audiences: ["aud-vendor"]
    claimMappings:
      username:
        claim: sub
        prefix: "gke-vendor:"
- name: gke-internal
  jwt:
    issuer:
      url: https://container.googleapis.com/v1/projects/internal/locations/europe-west1/clusters/b
      audiences: ["aud-internal"]
    claimMappings:
      username:
        claim: sub
        prefix: "gke-internal:"
`

// proxyConfig returns a document of the proxy kind with the given issuers
// entries, indented as list items under issuers.
func proxyConfig(entries string) string {
	return "apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1\nkind: AuthenticationConfiguration\nissuers:\n" + entries
}

// proxyEntry returns one issuers entry with a sub username claim.
func proxyEntry(name, url, audiences string) string {
	return `- name: ` + name + `
  jwt:
    issuer:
      url: ` + url + `
      audiences: ` + audiences + `
    claimMappings:
      username:
        claim: sub
        prefix: "` + name + `:"
`
}

func TestProxyAuthenticationConfigLoad(t *testing.T) {
	compiler := authenticationcel.NewDefaultCompiler()

	tests := []struct {
		name      string
		config    string
		wantErr   []string // substrings; empty means expect success
		wantNames []string
	}{
		{
			name:      "issuers on one host get the configured names",
			config:    validProxyConfig,
			wantNames: []string{"gke-vendor", "gke-internal"},
		},
		{
			name: "one issuer URL with disjoint audiences loads",
			config: proxyConfig(
				proxyEntry("gha-int", "https://token.actions.githubusercontent.com", `["aud-int"]`) +
					proxyEntry("gha-vendor", "https://token.actions.githubusercontent.com", `["aud-vendor"]`)),
			wantNames: []string{"gha-int", "gha-vendor"},
		},
		{
			name:      "a name can contain dots",
			config:    proxyConfig(proxyEntry("idp.example.com", "https://idp.example.com", `["aud"]`)),
			wantNames: []string{"idp.example.com"},
		},
		{
			name: "one issuer URL with a shared audience is refused",
			config: proxyConfig(`- name: gha-int
  jwt:
    issuer:
      url: https://token.actions.githubusercontent.com
      audiences: ["aud-int", "aud-shared"]
      audienceMatchPolicy: MatchAny
    claimMappings:
      username: {claim: sub, prefix: "gha-int:"}
` + proxyEntry("gha-vendor", "https://token.actions.githubusercontent.com", `["aud-shared"]`)),
			wantErr: []string{"issuers[0]", "issuers[1]", `"aud-shared"`},
		},
		{
			name: "a shared audience on different issuer URLs loads",
			config: proxyConfig(
				proxyEntry("a", "https://a.example.com", `["aud"]`) +
					proxyEntry("b", "https://b.example.com", `["aud"]`)),
			wantNames: []string{"a", "b"},
		},
		{
			name: "duplicate names are refused",
			config: proxyConfig(
				proxyEntry("corp", "https://a.example.com", `["aud"]`) +
					proxyEntry("corp", "https://b.example.com", `["aud"]`)),
			wantErr: []string{"issuers[0]", "issuers[1]", `"corp"`},
		},
		{
			name:    "a name that is not a DNS-1123 subdomain is refused",
			config:  proxyConfig(proxyEntry("Corp_A", "https://a.example.com", `["aud"]`)),
			wantErr: []string{"issuers[0].name"},
		},
		{
			name: "a missing name is refused",
			config: proxyConfig(`- jwt:
    issuer:
      url: https://a.example.com
      audiences: ["aud"]
    claimMappings:
      username: {claim: sub, prefix: "a:"}
`),
			wantErr: []string{"issuers[0].name"},
		},
		{
			name: "the same discoveryURL is refused",
			config: proxyConfig(`- name: a
  jwt:
    issuer:
      url: https://a.example.com
      discoveryURL: https://discovery.example.com/.well-known/openid-configuration
      audiences: ["aud"]
    claimMappings:
      username: {claim: sub, prefix: "a:"}
- name: b
  jwt:
    issuer:
      url: https://b.example.com
      discoveryURL: https://discovery.example.com/.well-known/openid-configuration
      audiences: ["aud"]
    claimMappings:
      username: {claim: sub, prefix: "b:"}
`),
			wantErr: []string{"issuers[0]", "issuers[1]", "discoveryURL"},
		},
		{
			name: "an entry that fails upstream validation is refused by index",
			config: proxyConfig(proxyEntry("a", "https://a.example.com", `["aud"]`) + `- name: b
  jwt:
    issuer:
      url: https://b.example.com
      audiences: ["aud"]
    claimMappings:
      username:
        expression: 'claims.sub +'
`),
			wantErr: []string{"issuers[1]"},
		},
		{
			name:    "an unknown field is refused",
			config:  proxyConfig(proxyEntry("a", "https://a.example.com", `["aud"]`)) + "extra: true\n",
			wantErr: []string{"unknown field"},
		},
		{
			name: "an unknown field inside jwt is refused",
			config: proxyConfig(`- name: a
  jwt:
    issuer:
      url: https://a.example.com
      audiencess: ["typo"]
    claimMappings:
      username: {claim: sub, prefix: "a:"}
`),
			wantErr: []string{"unknown field"},
		},
		{
			name:    "an empty issuers list is refused",
			config:  "apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1\nkind: AuthenticationConfiguration\nissuers: []\n",
			wantErr: []string{"issuers list must not be empty"},
		},
		{
			name: "a different kind is refused",
			config: `apiVersion: kube-oidc-proxy.rafpe.github.io/v1alpha1
kind: AuthorizationConfiguration
issuers: []
`,
			wantErr: []string{"expected AuthenticationConfiguration"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfiguration(writeAuthConfig(t, tc.config), compiler)

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
			if !cfg.ProxyKind {
				t.Fatal("ProxyKind = false, want true")
			}
			var names []string
			for _, e := range cfg.Entries {
				names = append(names, e.Name)
			}
			if !reflect.DeepEqual(names, tc.wantNames) {
				t.Fatalf("names = %v, want %v", names, tc.wantNames)
			}
		})
	}
}

// TestUpstreamConfigEntriesAreNamedByHost pins that the upstream kind keeps
// the host of the issuer URL as the issuer name.
func TestUpstreamConfigEntriesAreNamedByHost(t *testing.T) {
	cfg, err := LoadConfiguration(writeAuthConfig(t, validV1Config), authenticationcel.NewDefaultCompiler())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ProxyKind {
		t.Fatal("ProxyKind = true, want false")
	}
	var names []string
	for _, e := range cfg.Entries {
		names = append(names, e.Name)
	}
	if want := []string{"issuer1.example.com", "issuer2.example.com"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
}
