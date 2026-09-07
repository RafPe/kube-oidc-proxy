// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// ChartMetricsSurface is what the chart renders for metrics.enabled=true, as
// the e2e suite deploys it: the flag, the named container port and the
// dedicated Service. Deriving these from the chart rather than repeating them
// here means a chart that drifts from the binary fails the suite.
type ChartMetricsSurface struct {
	BindAddressArg string
	ContainerPort  int32
	PortName       string
	ServiceName    string
	ServicePort    int32
}

// ChartMetricsSurfaceFor renders the chart's Deployment and metrics Service
// with metrics enabled and extracts the surface above.
func ChartMetricsSurfaceFor(repoRoot string) (ChartMetricsSurface, error) {
	var s ChartMetricsSurface

	deploy, err := renderChartObject(repoRoot, "templates/deployment.yaml")
	if err != nil {
		return s, err
	}
	var d appsv1.Deployment
	if err := yaml.Unmarshal(deploy, &d); err != nil {
		return s, fmt.Errorf("decoding rendered Deployment: %w", err)
	}
	if len(d.Spec.Template.Spec.Containers) == 0 {
		return s, fmt.Errorf("rendered Deployment has no containers")
	}
	c := d.Spec.Template.Spec.Containers[0]
	for _, a := range c.Args {
		if strings.HasPrefix(a, "--metrics-bind-address=") {
			s.BindAddressArg = a
		}
	}
	if s.BindAddressArg == "" {
		return s, fmt.Errorf("rendered Deployment carries no --metrics-bind-address with metrics.enabled=true")
	}
	for _, p := range c.Ports {
		if p.Name != "" {
			s.ContainerPort, s.PortName = p.ContainerPort, p.Name
		}
	}
	if s.PortName == "" {
		return s, fmt.Errorf("rendered Deployment has no named container port")
	}

	svcBytes, err := renderChartObject(repoRoot, "templates/service-metrics.yaml")
	if err != nil {
		return s, err
	}
	var svc corev1.Service
	if err := yaml.Unmarshal(svcBytes, &svc); err != nil {
		return s, fmt.Errorf("decoding rendered metrics Service: %w", err)
	}
	if len(svc.Spec.Ports) != 1 {
		return s, fmt.Errorf("rendered metrics Service has %d ports, want 1", len(svc.Spec.Ports))
	}
	s.ServiceName = svc.Name
	s.ServicePort = svc.Spec.Ports[0].Port
	if svc.Spec.Ports[0].Name != s.PortName {
		return s, fmt.Errorf("rendered metrics Service port name %q != container port name %q", svc.Spec.Ports[0].Name, s.PortName)
	}
	return s, nil
}

// renderChartObject runs `helm template e2e <chart> --set metrics.enabled=true
// --show-only <template>` with the minimum single-issuer values.
func renderChartObject(repoRoot, template string) ([]byte, error) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		return nil, fmt.Errorf("the e2e suite renders the chart and needs helm on PATH: %w", err)
	}
	args := []string{"template", "e2e", filepath.Join(repoRoot, ChartPath),
		"--set", "oidc.issuerUrl=https://issuer.example.com", "--set", "oidc.clientId=e2e",
		"--set", "metrics.enabled=true", "--show-only", template}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(helm, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("helm %s: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}
