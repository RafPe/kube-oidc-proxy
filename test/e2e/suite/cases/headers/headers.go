// Copyright Jetstack Ltd. See LICENSE for details.

//go:build e2e

package headers

import (
	"fmt"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
)

var _ = framework.CasesDescribe("Headers", Label("shard-a"), func() {
	f := framework.NewDefaultFramework("headers")

	JustAfterEach(func(ctx SpecContext) {
		By("Deleting fake API Server")
		err := f.Helper().DeleteFakeAPIServer(ctx, f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not respond with any extra headers if none are set on the proxy", func(ctx SpecContext) {
		extraOIDCVolumes, fakeAPIServerURL, err := f.Helper().DeployFakeAPIServer(ctx, f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())

		By("Redeploying proxy to send traffic to fake API server")
		f.DeployProxyWith(ctx, extraOIDCVolumes, fmt.Sprintf("--server=%s", fakeAPIServerURL), "--certificate-authority=/fake-apiserver/ca.pem")

		resp := sendRequestToProxy(f)

		By("Ensuring no extra headers sent by proxy")
		for k := range resp.Header {
			if strings.HasPrefix(strings.ToLower(k), "impersonate-extra-") {
				Expect(fmt.Errorf("expected no extra user headers, got=%+v", resp.Header)).NotTo(HaveOccurred())
			}
		}
	})

	It("should respond with remote address and custom extra headers when they are set", func(ctx SpecContext) {
		By("Deploying fake API Server")
		extraOIDCVolumes, fakeAPIServerURL, err := f.Helper().DeployFakeAPIServer(ctx, f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())

		By("Redeploying proxy to send traffic to fake API server with extra headers set")
		f.DeployProxyWith(ctx, extraOIDCVolumes, fmt.Sprintf("--server=%s", fakeAPIServerURL), "--certificate-authority=/fake-apiserver/ca.pem",
			"--extra-user-header-client-ip", "--extra-user-headers=key1=foo,key2=foo,key1=bar")

		resp := sendRequestToProxy(f)

		By("Ensuring expected headers are present")
		cpyHeader := resp.Header.Clone()

		// Check expected headers
		for k, v := range map[string][]string{
			"Impersonate-Extra-Key1": {"foo", "bar"},
			"Impersonate-Extra-Key2": {"foo"},
		} {
			Expect(cpyHeader[k]).To(ConsistOf(v), "header %q, in headers %v", k, cpyHeader)

			cpyHeader.Del(k)
		}

		// Check expected client IP header
		// TODO: determine a reliable way to get ip to match
		headerIP, ok := cpyHeader["Impersonate-Extra-Remote-Client-Ip"]
		if !ok || len(headerIP) != 1 {
			Expect(fmt.Errorf("expected impersonate extra remote client ip user header, got=%v", resp.Header)).NotTo(HaveOccurred())
		}

		cpyHeader.Del("Impersonate-Extra-Remote-Client-Ip")

		By("Ensuring no extra user headers where added")
		for k := range cpyHeader {
			if strings.HasPrefix(strings.ToLower(k), "impersonate-extra-") {
				Expect(fmt.Errorf("expected no impersonate extra user headers, got=%+v", resp.Header)).NotTo(HaveOccurred())
			}
		}
	})
})

func sendRequestToProxy(f *framework.Framework) *http.Response {
	By("Building request to proxy")
	proxyConfig := f.NewProxyRestConfig()
	requester := f.Helper().NewRequester(proxyConfig.Transport, proxyConfig.BearerToken)

	By("Sending request to proxy")
	reqURL := fmt.Sprintf("%s/foo/bar", proxyConfig.Host)
	_, resp, err := requester.Get(reqURL)
	Expect(err).NotTo(HaveOccurred())

	return resp
}
