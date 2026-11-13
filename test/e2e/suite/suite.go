// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package suite

import (
	"encoding/json"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
	"github.com/rafpe/kube-oidc-proxy/test/environment"
)

// env is the provisioned cluster. Only Ginkgo process 1 creates it, and only
// that process destroys it.
var env *environment.Environment

// The first function runs on Ginkgo process 1 only: it provisions the
// environment and returns the paths locating it. The second runs on every
// process, including the first, and is the one place framework.SetDefaultConfig
// is called, so a parallel run gives every process the same configuration.
var _ = SynchronizedBeforeSuite(func() []byte {
	var err error
	env, err = environment.New(1, 0)
	Expect(err).NotTo(HaveOccurred(), "provisioning environment")

	Expect(env.Create()).To(Succeed(), "creating environment")

	data, err := json.Marshal(config.Config{
		KubeConfigPath: env.KubeConfigPath(),
		Kubectl:        filepath.Join(env.RootPath(), "bin", "kubectl"),
		RepoRoot:       env.RootPath(),
	})
	Expect(err).NotTo(HaveOccurred(), "encoding test config")
	return data
}, func(data []byte) {
	var cfg config.Config
	Expect(json.Unmarshal(data, &cfg)).To(Succeed(), "decoding test config")
	Expect(framework.SetDefaultConfig(cfg)).To(Succeed(), "setting test config")
})

var _ = SynchronizedAfterSuite(func() {},
	func() {
		if env != nil {
			Expect(env.Destroy()).To(Succeed(), "destroying environment")
		}
	},
)
