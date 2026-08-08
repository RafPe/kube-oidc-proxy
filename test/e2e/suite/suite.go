// Copyright Jetstack Ltd. See LICENSE for details.
package suite

import (
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/environment"
)

var (
	env *environment.Environment
	cfg = framework.DefaultConfig
)

var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	env, err = environment.New(1, 0)
	if err != nil {
		klog.Fatalf("Error provisioning environment: %s", err)
	}

	if err := env.Create(); err != nil {
		klog.Fatalf("Error creating environment: %s", err)
	}

	cfg.KubeConfigPath = env.KubeConfigPath()
	cfg.Kubectl = filepath.Join(env.RootPath(), "bin", "kubectl")
	cfg.RepoRoot = env.RootPath()
	cfg.Environment = env

	if err := framework.DefaultConfig.Validate(); err != nil {
		klog.Fatalf("Invalid test config: %s", err)
	}

	return nil
}, func([]byte) {
})

var _ = SynchronizedAfterSuite(func() {},
	func() {
		if env != nil {
			if err := env.Destroy(); err != nil {
				klog.Fatalf("Failed to destroy environment: %s", err)
			}
		}
	},
)
