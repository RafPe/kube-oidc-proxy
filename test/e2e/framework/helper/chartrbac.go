// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

// ChartPath is the Helm chart, relative to the repository root.
const ChartPath = "chart/kube-oidc-proxy"

// ChartRBACValuesFile is the values file the e2e suite renders the chart's
// ClusterRole with. It declares the extra key the impersonation cases send
// (rbac.userExtras) and nothing else, so what the suite grants the proxy is
// exactly what the chart grants an operator who sets that value.
const ChartRBACValuesFile = "test/e2e/framework/helper/testdata/chart-rbac-values.yaml"

// ChartClusterRoleRules renders the chart's ClusterRole template and returns
// its rules. The e2e suite deploys the proxy with these rules rather than a
// hand-written copy, so a permission the proxy needs but the chart does not
// grant fails the suite instead of surviving until an operator hits it.
//
// Rendering shells out to the helm binary; the suite already requires it in
// CI and the Makefile checks for it locally.
func ChartClusterRoleRules(repoRoot string, valuesFiles ...string) ([]rbacv1.PolicyRule, error) {
	role, err := RenderChartClusterRole(repoRoot, valuesFiles...)
	if err != nil {
		return nil, err
	}
	return role.Rules, nil
}

// RenderChartClusterRole renders templates/clusterrole.yaml of the chart with
// the given values files (paths relative to repoRoot or absolute) and decodes
// it.
func RenderChartClusterRole(repoRoot string, valuesFiles ...string) (*rbacv1.ClusterRole, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return nil, fmt.Errorf("the e2e suite renders the chart's RBAC and needs helm on PATH: %w", err)
	}

	args := []string{"template", "e2e", filepath.Join(repoRoot, ChartPath), "--show-only", "templates/clusterrole.yaml"}
	for _, f := range valuesFiles {
		if !filepath.IsAbs(f) {
			f = filepath.Join(repoRoot, f)
		}
		args = append(args, "-f", f)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(helm, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helm %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}

	var role rbacv1.ClusterRole
	if err := yaml.Unmarshal(stdout.Bytes(), &role); err != nil {
		return nil, fmt.Errorf("decoding rendered ClusterRole: %w\n%s", err, stdout.String())
	}
	if role.Kind != "ClusterRole" || len(role.Rules) == 0 {
		return nil, fmt.Errorf("rendered %s is not a ClusterRole with rules:\n%s", ChartPath, stdout.String())
	}
	return &role, nil
}

// RulesAllow reports whether the rules grant verb on group/resource. It
// mirrors the exact-match part of RBAC evaluation, which is all the chart's
// ClusterRole uses: no wildcard resources, no resourceNames.
func RulesAllow(rules []rbacv1.PolicyRule, group, resource, verb string) bool {
	for _, r := range rules {
		if !contains(r.APIGroups, group) || !contains(r.Resources, resource) {
			continue
		}
		if contains(r.Verbs, verb) || contains(r.Verbs, "*") {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
