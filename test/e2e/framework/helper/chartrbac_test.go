// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
)

// repoRoot locates the repository from this file, so the test needs no
// environment variable: helper/ -> framework/ -> e2e/ -> test/ -> root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", ".."))
	if _, err := os.Stat(filepath.Join(root, ChartPath, "Chart.yaml")); err != nil {
		t.Fatalf("chart not found under %s: %v", root, err)
	}
	return root
}

// grant is one (apiGroup, resource, verb) triple a ClusterRole allows.
type grant struct{ group, resource, verb string }

// proxyNeeds is every permission the proxy exercises against the API server
// whatever its configuration. The list of extra keys comes from the proxy
// package, so a key added to the outbound impersonation request without a
// matching grant fails the guard rather than as a 403 on an operator's
// cluster.
func proxyNeeds() []grant {
	needs := []grant{
		// Outbound impersonation of the mapped identity, or of the one
		// kubectl --as asked for.
		{"", "users", "impersonate"},
		{"", "groups", "impersonate"},
		{"", "serviceaccounts", "impersonate"},
		{"authentication.k8s.io", "uids", "impersonate"},
		// Authorizing inbound impersonation (kubectl --as).
		{"authorization.k8s.io", "subjectaccessreviews", "create"},
		// Validating passthrough tokens.
		{"authentication.k8s.io", "tokenreviews", "create"},
	}
	// Every extra key the proxy itself puts on an outbound request, plus the
	// credential ID the Kubernetes authenticator adds to every OIDC identity.
	// The API server lowercases extra keys taken from headers before
	// authorizing them, so the grant must be lowercase.
	for _, key := range append(proxy.FixedImpersonationExtraKeys(), user.CredentialIDKey) {
		needs = append(needs, extraGrant(key))
	}
	return needs
}

func extraGrant(key string) grant {
	return grant{"authentication.k8s.io", "userextras/" + strings.ToLower(key), "impersonate"}
}

// TestChartGrantsWhatTheProxyNeeds is the guard between the code and the
// chart: every permission the proxy exercises against the API server must be
// granted by the chart's ClusterRole as rendered with default values.
func TestChartGrantsWhatTheProxyNeeds(t *testing.T) {
	rules, err := ChartClusterRoleRules(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range proxyNeeds() {
		if !RulesAllow(rules, n.group, n.resource, n.verb) {
			t.Errorf("chart ClusterRole does not grant %s on %q/%s; the proxy needs it", n.verb, n.group, n.resource)
		}
	}
}

// TestChartGrantsNothingElse is the other half of the guard: every
// (apiGroup, resource, verb) the rendered ClusterRole allows must be one the
// proxy needs or one the configuration declares as an extra key. A rule that
// pairs a verb with a resource that never sees it, or a grant left behind
// when the proxy stopped using it, fails here.
func TestChartGrantsNothingElse(t *testing.T) {
	root := repoRoot(t)
	cases := []struct {
		name      string
		values    []string
		extraKeys []string
	}{
		{name: "defaults"},
		{name: "e2e values", values: []string{ChartRBACValuesFile}, extraKeys: []string{"oktoimpersonateextra"}},
		{
			name:      "declared extra keys",
			values:    []string{declaredExtraKeysValues(t)},
			extraKeys: []string{"example.com/actor", "example.com/env", "example.com/tier", "example.com/team"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := ChartClusterRoleRules(root, tc.values...)
			if err != nil {
				t.Fatal(err)
			}

			allowed := map[grant]bool{}
			for _, n := range proxyNeeds() {
				allowed[n] = true
			}
			for _, key := range tc.extraKeys {
				allowed[extraGrant(key)] = true
			}

			for _, r := range rules {
				if len(r.ResourceNames) > 0 || len(r.NonResourceURLs) > 0 {
					t.Errorf("chart ClusterRole rule %+v uses resourceNames or nonResourceURLs, which the proxy never needs", r)
				}
				for _, g := range r.APIGroups {
					for _, res := range r.Resources {
						for _, v := range r.Verbs {
							if !allowed[grant{g, res, v}] {
								t.Errorf("chart ClusterRole grants %s on %q/%s, which the proxy does not need", v, g, res)
							}
						}
					}
				}
			}
		})
	}
}

// TestChartGrantsDeclaredExtraKeys covers the operator-driven grants: keys
// declared in claimMappings.extra, in extraImpersonationHeaders.headers and
// in rbac.userExtras must all render, lowercased, as userextras grants.
func TestChartGrantsDeclaredExtraKeys(t *testing.T) {
	root := repoRoot(t)
	values := declaredExtraKeysValues(t)

	rules, err := ChartClusterRoleRules(root, values)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"example.com/actor", "example.com/env", "example.com/tier", "example.com/team"} {
		if !RulesAllow(rules, "authentication.k8s.io", "userextras/"+key, "impersonate") {
			t.Errorf("declared extra key %q is not granted as userextras/%s", key, key)
		}
	}

	// The suite's own values file must grant the key the impersonation cases use.
	rules, err = ChartClusterRoleRules(root, ChartRBACValuesFile)
	if err != nil {
		t.Fatal(err)
	}
	if !RulesAllow(rules, "authentication.k8s.io", "userextras/oktoimpersonateextra", "impersonate") {
		t.Errorf("%s does not grant userextras/oktoimpersonateextra, which the impersonation e2e cases send", ChartRBACValuesFile)
	}
}

// declaredExtraKeysValues writes a values file that declares one extra key
// each in claimMappings.extra and rbac.userExtras and two in
// extraImpersonationHeaders.headers, mixed case included.
func declaredExtraKeysValues(t *testing.T) string {
	t.Helper()
	values := filepath.Join(t.TempDir(), "values.yaml")
	content := `
extraImpersonationHeaders:
  headers: example.com/env=prod,Example.com/Tier=gold
rbac:
  userExtras:
    - Example.com/Team
authenticationConfig:
  content: |
    apiVersion: apiserver.config.k8s.io/v1
    kind: AuthenticationConfiguration
    jwt:
    - issuer:
        url: https://issuer.example.com
        audiences: ["kube-oidc-proxy"]
      claimMappings:
        username:
          claim: sub
          prefix: "ex:"
        extra:
        - key: example.com/actor
          valueExpression: claims.actor
`
	if err := os.WriteFile(values, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return values
}
