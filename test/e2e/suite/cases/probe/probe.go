// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package probe

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

var _ = framework.CasesDescribe("Readiness Probe", Label("shard-a"), func() {
	f := framework.NewDefaultFramework("readiness-probe")

	It("Should not become ready if the issuer is unavailable", func(ctx SpecContext) {
		By("Deleting the Issuer so no longer becomes reachable")
		Expect(f.Helper().DeleteIssuer(ctx, f.Namespace.Name)).NotTo(HaveOccurred())

		By("Deleting the current proxy that is ready")
		Expect(f.Helper().DeleteProxy(ctx, f.Namespace.Name)).NotTo(HaveOccurred())

		By("Deploying the Proxy should never become ready as the issuer is unavailable")
		// This deploy is expected to time out, so do not wait out the full
		// default budget; the readiness probe reports every 3 seconds.
		f.Helper().DeployReadyTimeout = 15 * time.Second
		_, _, err := f.Helper().DeployProxy(ctx, f.Namespace, f.IssuerURL(),
			f.ClientID(), f.IssuerKeyBundle(), nil)
		// Error should occur (not ready)
		Expect(err).To(HaveOccurred())
	})

	It("Should continue to be ready even if the issuer becomes unavailable", func(ctx SpecContext) {
		By("Deleting the Issuer so no longer becomes reachable")
		Expect(f.Helper().DeleteIssuer(ctx, f.Namespace.Name)).NotTo(HaveOccurred())

		// Checked continuously, not once after a pause: the readiness probe runs
		// every 3s and fails the pod after three misses, so a proxy that wrongly
		// ties readiness to the issuer turns unready well within this window.
		By("Checking the proxy stays ready while the issuer is gone")
		Consistently(func() (bool, error) {
			return f.Helper().DeploymentReady(ctx, f.Namespace.Name, kind.ProxyImageName)
		}).WithTimeout(30 * time.Second).WithPolling(time.Second).Should(BeTrue())
	})
})
