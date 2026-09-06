// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"k8s.io/client-go/kubernetes"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
)

// Helper provides methods for common operations needed during tests.
type Helper struct {
	cfg *config.Config

	KubeClient kubernetes.Interface
}

func NewHelper(cfg *config.Config) *Helper {
	return &Helper{
		cfg: cfg,
	}
}

// RepoRoot is the repository checkout the suite runs from, for helpers that
// render the chart.
func (h *Helper) RepoRoot() string {
	return h.cfg.RepoRoot
}
