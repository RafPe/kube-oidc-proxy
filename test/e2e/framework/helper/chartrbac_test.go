// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"

	accesslogging "github.com/rafpe/kube-oidc-proxy/pkg/proxy/logging"
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

// TestChartGrantsWhatTheProxyNeeds is the guard between the code and the
// chart: every permission the proxy exercises against the API server must be
// granted by the chart's ClusterRole as rendered with default values. The
// list of extra keys comes from the proxy package, so a key added to the
// outbound impersonation request without a matching grant fails here rather
// than as a 403 on an operator's cluster.
func TestChartGrantsWhatTheProxyNeeds(t *testing.T) {
	rules, err := ChartClusterRoleRules(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}

	type need struct{ group, resource, verb string }
	needs := []need{
		// Outbound impersonation of the mapped identity.
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
	for _, key := range append(accesslogging.FixedImpersonationExtraKeys(), user.CredentialIDKey) {
		needs = append(needs, need{"authentication.k8s.io", "userextras/" + strings.ToLower(key), "impersonate"})
	}

	for _, n := range needs {
		if !RulesAllow(rules, n.group, n.resource, n.verb) {
			t.Errorf("chart ClusterRole does not grant %s on %q/%s; the proxy needs it", n.verb, n.group, n.resource)
		}
	}
}

// TestChartGrantsDeclaredExtraKeys covers the operator-driven grants: keys
// declared in claimMappings.extra, in extraImpersonationHeaders.headers and
// in rbac.userExtras must all render, lowercased, as userextras grants.
func TestChartGrantsDeclaredExtraKeys(t *testing.T) {
	root := repoRoot(t)
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
