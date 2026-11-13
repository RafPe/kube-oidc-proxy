// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
)

// fakeKubectl installs a shell script in place of kubectl that records every
// invocation, one per line, and returns the path of that record.
func fakeKubectl(t *testing.T) (kubectl, record string) {
	t.Helper()
	dir := t.TempDir()
	record = filepath.Join(dir, "calls.log")
	kubectl = filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\necho \"$@\" >> " + record + "\n"
	if err := os.WriteFile(kubectl, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return kubectl, record
}

func TestWaitForDeploymentReadyTimeoutDumpsPodsAndEvents(t *testing.T) {
	kubectl, record := fakeKubectl(t)

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-oidc-proxy-e2e", Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "kube-oidc-proxy-e2e"}},
		},
		Status: appsv1.DeploymentStatus{ReadyReplicas: 0},
	}

	h := NewHelper(&config.Config{Kubectl: kubectl, KubeConfigPath: "kubeconfig"})
	h.KubeClient = fake.NewSimpleClientset(deploy)

	err := h.WaitForDeploymentReady("ns", deploy.Name, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("expected a deadline error, got %q", err)
	}

	b, rerr := os.ReadFile(record)
	if rerr != nil {
		t.Fatalf("kubectl was never invoked: %v", rerr)
	}
	calls := strings.TrimSpace(string(b))

	for _, want := range []string{
		"describe deployment kube-oidc-proxy-e2e",
		"describe pods -l app=kube-oidc-proxy-e2e",
		"get events --sort-by=.lastTimestamp",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("expected a kubectl call containing %q on timeout, got:\n%s", want, calls)
		}
	}
}
