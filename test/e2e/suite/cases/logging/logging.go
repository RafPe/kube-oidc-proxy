// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/suite/cases/sharedtests"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

const (
	// defaultUsername is the identity the suite's mock issuer mints tokens for
	// and the one the proxy's e2e RBAC knows about.
	defaultUsername = "user@example.com"

	// proxySelector matches the proxy pod whose log stream every spec reads.
	proxySelector = "app=" + kind.ProxyImageName

	// fakeAPIServerSelector matches the fake API server pod, used by the
	// upstream-forwarding spec.
	fakeAPIServerSelector = "app=" + kind.FakeAPIServerImageName
)

var _ = framework.CasesDescribe("Logging", Label("shard-b"), func() {
	f := framework.NewDefaultFramework("logging")

	It("emits every record as one JSON object per line with schema_version and component", func() {
		recs, raw := records(f)
		Expect(recs).NotTo(BeEmpty(), raw)
		for _, r := range recs {
			Expect(r).To(HaveKeyWithValue("schema_version", float64(1)))
			Expect(r).To(HaveKey("component"))
		}
		// Decoded here, not merely prefix-checked: a line such as "{invalid"
		// begins with a brace and is not a record, and the contract this spec
		// exists to pin is that every line the proxy writes decodes as one JSON
		// object. It fails on the first line that does not.
		for _, line := range nonEmptyLines(raw) {
			var rec map[string]any
			Expect(json.Unmarshal([]byte(line), &rec)).To(Succeed(),
				"non-JSON line in proxy output: %s", line)
			Expect(rec).NotTo(BeNil(),
				"line decoded to JSON null rather than an object: %s", line)
		}
	})

	It("records startup configuration and every configured issuer", func() {
		recs, _ := records(f)
		Expect(sharedtests.ByEvent(recs, "proxy.config.loaded")).To(HaveLen(1))

		// One record per configured issuer, not merely one record: the
		// expected set is derived from the issuer the framework configured the
		// proxy with, so it follows a deploy that configures more than one.
		want := configuredIssuerNames(f)
		configured := sharedtests.ByEvent(recs, "oidc.issuer.configured")
		Expect(configured).To(HaveLen(len(want)))

		var got []string
		for _, r := range configured {
			name, _ := r["issuer_name"].(string)
			Expect(name).NotTo(BeEmpty(), "oidc.issuer.configured with no issuer_name: %v", r)
			got = append(got, name)
		}
		Expect(got).To(ConsistOf(want))

		Expect(sharedtests.ByEvent(recs, "readiness.proxy.ready")).To(HaveLen(1))
	})

	It("correlates a successful request across the access record, the terminal record and the response header", func() {
		grantPodList(f, defaultUsername)

		resp := doRequest(f, validToken(f), nil)
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		id := resp.Header.Get("Audit-ID")
		Expect(id).To(MatchRegexp(`^[0-9a-f-]{36}$`))

		Eventually(func() []map[string]any {
			recs, _ := records(f)
			return sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)
		}, 20*time.Second, time.Second).Should(HaveLen(1))
		recs, _ := records(f)
		dec := sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)[0]
		Expect(dec).To(HaveKeyWithValue("event", "AuSuccess"))
		Expect(dec).To(HaveKeyWithValue("auth_method", "oidc"))
		Expect(dec).To(HaveKeyWithValue("k8s_resource", "pods"))
		Expect(dec).To(HaveKey("issuer_name"))
		done := sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.response.completed"), id)
		Expect(done).To(HaveLen(1))
		Expect(done[0]).To(HaveKeyWithValue("http_status", float64(200)))
		Expect(done[0]).To(HaveKeyWithValue("termination", "normal"))
	})

	It("does not adopt a client-supplied Audit-ID", func() {
		resp := doRequest(f, validToken(f), map[string]string{"Audit-ID": "client-chosen"})
		Expect(resp.Header.Get("Audit-ID")).NotTo(Equal("client-chosen"))
		recs, _ := records(f)
		Expect(sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), "client-chosen")).To(BeEmpty())
	})

	It("records a rejected token with a reason and never the token itself", func() {
		tok := "eyJ.invalid.token"
		resp := doRequest(f, tok, nil)
		Expect(resp.StatusCode).To(Equal(http.StatusUnauthorized))
		id := resp.Header.Get("Audit-ID")
		Eventually(func() []map[string]any {
			recs, _ := records(f)
			return sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)
		}, 20*time.Second, time.Second).Should(HaveLen(1))
		recs, raw := records(f)
		Expect(sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)[0]).To(HaveKeyWithValue("reason", "unauthorized"))
		Expect(raw).NotTo(ContainSubstring(tok))
		// The stream is checked for an unmasked credential rather than for the
		// header name: at -v=10 client-go's debug round tripper prints a curl
		// command naming the Authorization header, with its value already
		// masked, for the proxy's own requests to the API server.
		Expect(raw).NotTo(MatchRegexp(`(?i)bearer\s+[A-Za-z0-9._-]{20,}`))
	})

	It("records an impersonation denial with reason and target", func() {
		// The impersonation target is a user the e2e RBAC does allow, paired
		// with a group it does not: a group header on its own never reaches a
		// SubjectAccessReview, so the denial being asserted here would not
		// happen. The SAR clears the user and refuses the group.
		resp := doRequest(f, validToken(f), map[string]string{
			"Impersonate-User":  "ok-to-impersonate@nodomain.dev",
			"Impersonate-Group": "system:masters",
		})
		Expect(resp.StatusCode).To(Equal(http.StatusForbidden))
		id := resp.Header.Get("Audit-ID")
		Eventually(func() []map[string]any {
			recs, _ := records(f)
			return sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)
		}, 20*time.Second, time.Second).Should(HaveLen(1))
		recs, _ := records(f)
		dec := sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)[0]
		Expect(dec).To(HaveKeyWithValue("event", "AuFail"))
		Expect(dec).To(HaveKeyWithValue("reason", "impersonation_denied"))
		Expect(dec).To(HaveKeyWithValue("target_kind", "group"))
	})

	It("drops forwarded headers from an untrusted client and says so at WARN", func() {
		resp := doRequest(f, validToken(f), map[string]string{"X-Forwarded-For": "9.9.9.9"})
		id := resp.Header.Get("Audit-ID")
		Eventually(func() []map[string]any {
			recs, _ := records(f)
			return sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.headers.dropped"), id)
		}, 20*time.Second, time.Second).Should(HaveLen(1))
		recs, _ := records(f)
		Expect(sharedtests.WithRequestID(sharedtests.ByEvent(recs, "request.access.decided"), id)[0]).NotTo(HaveKeyWithValue("src_ip", "9.9.9.9"))
	})

	It("bridges client-go output as component=k8s without event_type", func() {
		recs, _ := records(f) // suite runs at --v=10, so client-go transport debug lines exist
		k8s := sharedtests.ByComponent(recs, "k8s")
		Expect(k8s).NotTo(BeEmpty())
		for _, r := range k8s {
			Expect(r).NotTo(HaveKey("event_type"))
		}
	})

	It("forwards the request id to the upstream API server", func() {
		extraOIDCVolumes, fakeAPIServerURL, err := f.Helper().DeployFakeAPIServer(f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())
		f.DeployProxyWith(extraOIDCVolumes, fmt.Sprintf("--server=%s", fakeAPIServerURL), "--certificate-authority=/fake-apiserver/ca.pem")
		resp := doRequest(f, validToken(f), nil)
		id := resp.Header.Get("Audit-ID")

		// The fake API server logs header names without their values, so the
		// value that reached it is observed through the echo instead: it
		// reflects every request header onto its response, and the proxy sets
		// Audit-ID on the response itself, so the id arrives twice only if the
		// upstream received it.
		Expect(resp.Header.Values("Audit-ID")).To(ContainElements(id, id),
			"the upstream did not echo back the request id the proxy minted")
		Eventually(func() string { return fakeAPIServerLogs(f) }, 20*time.Second, time.Second).
			Should(ContainSubstring("Audit-Id"))
	})
})

// records returns the proxy's decoded records and the raw log text.
func records(f *framework.Framework) ([]map[string]any, string) {
	recs, raw, err := f.Helper().ProxyLogRecords(f.Namespace.Name, proxySelector)
	Expect(err).NotTo(HaveOccurred())

	return recs, raw
}

// fakeAPIServerLogs returns the raw logs of the fake API server the proxy is
// pointed at.
func fakeAPIServerLogs(f *framework.Framework) string {
	logs, err := f.Helper().PodLogs(f.Namespace.Name, fakeAPIServerSelector)
	Expect(err).NotTo(HaveOccurred())

	return logs
}

// configuredIssuerNames returns the issuer_name the proxy records for each
// issuer the framework configured it with. The default deploy passes exactly
// one --oidc-issuer-url, the mock issuer the framework stood up, and a record
// names an issuer by its host: the full issuer URL is never logged.
func configuredIssuerNames(f *framework.Framework) []string {
	return []string{f.IssuerURL().Host}
}

// nonEmptyLines splits raw log text into the lines that carry content.
func nonEmptyLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}

	return out
}

// validToken mints a token the proxy's OIDC authenticator accepts.
func validToken(f *framework.Framework) string {
	payload, err := f.Helper().NewTokenPayloadForIdentity(f.IssuerURL(), f.ClientID(),
		defaultUsername, []string{"group-1"}, time.Now().Add(time.Minute*10))
	Expect(err).NotTo(HaveOccurred())

	signedToken, err := f.Helper().SignToken(f.IssuerKeyBundle(), payload)
	Expect(err).NotTo(HaveOccurred())

	return signedToken
}

// doRequest lists pods through the proxy with the given bearer token and extra
// headers. The request is built by hand rather than through a client-go client
// so the specs can send headers a REST config cannot express and can read the
// response headers the proxy set, whatever the status.
func doRequest(f *framework.Framework, token string, headers map[string]string) *http.Response {
	config := f.NewProxyRestConfig()

	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/api/v1/namespaces/%s/pods", config.Host, f.Namespace.Name), nil)
	Expect(err).NotTo(HaveOccurred())

	req.Header.Set("Authorization", "bearer "+token)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := (&http.Client{Transport: config.Transport}).Do(req)
	Expect(err).NotTo(HaveOccurred())

	// The body is read and closed here so the connection is released; the
	// specs assert on the status and the headers only.
	_, err = io.Copy(io.Discard, resp.Body)
	Expect(err).NotTo(HaveOccurred())
	Expect(resp.Body.Close()).To(Succeed())

	return resp
}

// grantPodList gives username permission to list pods in the test namespace,
// so a request that is meant to be authorized end to end is not refused by the
// API server after the proxy has allowed it.
func grantPodList(f *framework.Framework, username string) {
	role, err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "logging-pods-",
		},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
		},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())

	_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(),
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: "logging-pods-",
			},
			Subjects: []rbacv1.Subject{{Name: username, Kind: "User"}},
			RoleRef:  rbacv1.RoleRef{Name: role.Name, Kind: "Role"},
		}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}
