// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
)

// Helper provides methods for common operations needed during tests.
type Helper struct {
	cfg *config.Config

	// KubeClient talks to the test cluster directly, as its admin, rather
	// than through the proxy.
	KubeClient kubernetes.Interface

	// DeployReadyTimeout bounds how long a deployed app (proxy, issuer,
	// webhook) may take to become ready. Zero means DefaultDeployReadyTimeout.
	// A spec that expects a deploy to never become ready sets this short so it
	// does not wait out the whole default budget.
	DeployReadyTimeout time.Duration
}

// DefaultDeployReadyTimeout is the deploy budget when none is set. Normal
// deploys take 4 to 8 seconds on the CI kind cluster; the budget has to ride
// out a single container-runtime stall (30 seconds observed in run
// 42305084629) without hiding a proxy that genuinely never comes up.
const DefaultDeployReadyTimeout = 60 * time.Second

func (h *Helper) deployReadyTimeout() time.Duration {
	if h.DeployReadyTimeout > 0 {
		return h.DeployReadyTimeout
	}
	return DefaultDeployReadyTimeout
}

// NewHelper returns a Helper for the cluster cfg describes, which kubeClient
// must already be connected to.
func NewHelper(cfg *config.Config, kubeClient kubernetes.Interface) *Helper {
	return &Helper{
		cfg:        cfg,
		KubeClient: kubeClient,
	}
}

// RepoRoot is the repository checkout the suite runs from, for helpers that
// render the chart.
func (h *Helper) RepoRoot() string {
	return h.cfg.RepoRoot
}
