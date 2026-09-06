// Copyright Jetstack Ltd. See LICENSE for details.

// Package metrics scrapes the proxy's metrics endpoint inside the kind
// cluster and asserts on what the chart-rendered configuration exposes.
package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/kind"
)

const (
	defaultUsername = "user@example.com"

	metricBuildInfo     = "kube_oidc_proxy_build_info"
	metricRequestsTotal = "kube_oidc_proxy_requests_total"
	metricDurationCount = "kube_oidc_proxy_request_duration_seconds_count"
	metricLongRunning   = "kube_oidc_proxy_long_running_requests"
	metricAuthnAttempts = "kube_oidc_proxy_authentication_attempts_total"
	metricDecisions     = "kube_oidc_proxy_access_decisions_total"
	metricIssuerInit    = "kube_oidc_proxy_oidc_issuer_initialized"
	metricReady         = "kube_oidc_proxy_ready"
)

var knownVerbs = map[string]bool{"get": true, "list": true, "watch": true, "create": true, "update": true, "patch": true,
	"delete": true, "deletecollection": true, "proxy": true, "connect": true, "other": true}
var knownScopes = map[string]bool{"cluster": true, "namespace": true, "resource": true, "none": true}

var _ = framework.CasesDescribe("Metrics", Label("shard-a"), func() {
	f := framework.NewDefaultFramework("metrics")

	var surface helper.ChartMetricsSurface

	// The proxy is deployed with exactly the flag and the named container
	// port the chart renders, and the metrics Service mirrors the chart's
	// dedicated Service down to the named targetPort, so the suite scrapes
	// what an operator installs. Only the selector differs: the harness pods
	// carry the harness's own labels.
	f.BeforeProxyDeploy = func() {
		var err error
		surface, err = helper.ChartMetricsSurfaceFor(f.Helper().RepoRoot())
		Expect(err).NotTo(HaveOccurred())
		f.ExtraProxyArgs = []string{surface.BindAddressArg}
		f.ExtraProxyExtras = &helper.ProxyExtras{Ports: []corev1.ContainerPort{{
			Name:          surface.PortName,
			ContainerPort: surface.ContainerPort,
			Protocol:      corev1.ProtocolTCP,
		}}}
	}

	// The framework creates the namespace and deploys the proxy in a
	// JustBeforeEach (framework.go: `JustBeforeEach(f.BeforeEach)`), so this
	// must be a JustBeforeEach declared after it, not a BeforeEach, or
	// f.Namespace is still nil here.
	JustBeforeEach(func() {
		_, err := f.Helper().KubeClient.CoreV1().Services(f.Namespace.Name).Create(context.TODO(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: metricsServiceName()},
			Spec: corev1.ServiceSpec{
				Selector: map[string]string{"app": kind.ProxyImageName},
				Ports: []corev1.ServicePort{{
					Name:       surface.PortName,
					Port:       surface.ServicePort,
					TargetPort: intstr.FromString(surface.PortName),
					Protocol:   corev1.ProtocolTCP,
				}},
			},
		}, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())

		// Creating a Service does not publish its endpoints synchronously;
		// wait until the first scrape through it succeeds.
		Eventually(func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := scrapeRaw(ctx, f, surface)
			return err
		}, 30*time.Second, time.Second).Should(Succeed())
	})

	It("serves build information and the runtime collectors", func() {
		samples := mustSamples(f, surface)
		v, ok := helper.SampleValue(samples, metricBuildInfo, nil)
		Expect(ok).To(BeTrue(), "build_info missing")
		Expect(v).To(Equal(1.0))
		_, ok = helper.SampleValue(samples, "go_goroutines", nil)
		Expect(ok).To(BeTrue(), "go collector missing")
	})

	It("reports the configured issuer as initialized and the proxy as ready", func() {
		samples := mustSamples(f, surface)
		v, ok := helper.SampleValue(samples, metricIssuerInit, map[string]string{"issuer_name": f.IssuerURL().Host})
		Expect(ok).To(BeTrue(), "issuer gauge missing for %s", f.IssuerURL().Host)
		Expect(v).To(Equal(1.0))
		v, _ = helper.SampleValue(samples, metricReady, nil)
		Expect(v).To(Equal(1.0))
	})

	It("counts an allowed list and a rejected token with closed-set labels", func() {
		grantPods(f, defaultUsername, "get", "list", "watch")
		Expect(doRequest(f, validToken(f)).StatusCode).To(Equal(http.StatusOK))
		Expect(doRequest(f, "eyJ.invalid.token").StatusCode).To(Equal(http.StatusUnauthorized))

		Eventually(func() (float64, error) {
			return sampleValue(f, surface, metricRequestsTotal,
				map[string]string{"k8s_verb": "list", "scope": "namespace", "code": "200", "termination": "normal"})
		}, 20*time.Second, time.Second).Should(BeNumerically(">=", 1))

		samples := mustSamples(f, surface)
		v, _ := helper.SampleValue(samples, metricAuthnAttempts, map[string]string{"auth_method": "oidc", "outcome": "rejected"})
		Expect(v).To(BeNumerically(">=", 1))
		v, _ = helper.SampleValue(samples, metricDecisions, map[string]string{"auth_method": "none", "decision": "deny", "reason": "unauthorized"})
		Expect(v).To(BeNumerically(">=", 1))
		v, _ = helper.SampleValue(samples, metricDecisions, map[string]string{"auth_method": "oidc", "decision": "allow"})
		Expect(v).To(BeNumerically(">=", 1))
	})

	It("gauges an open watch and releases it, without timing it", func() {
		grantPods(f, defaultUsername, "get", "list", "watch")
		// RBAC propagation is not synchronous either: open the watch only
		// once a list with the same grant succeeds.
		Eventually(func() int {
			return doRequest(f, validToken(f)).StatusCode
		}, 20*time.Second, time.Second).Should(Equal(http.StatusOK))

		w, err := f.ProxyClient.CoreV1().Pods(f.Namespace.Name).Watch(context.TODO(), metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(w.Stop)

		Eventually(func() (float64, error) {
			return sampleValue(f, surface, metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"})
		}, 20*time.Second, time.Second).Should(Equal(1.0))

		w.Stop()
		Eventually(func() (float64, error) {
			return sampleValue(f, surface, metricLongRunning, map[string]string{"k8s_verb": "watch", "scope": "namespace"})
		}, 30*time.Second, time.Second).Should(Equal(0.0))

		_, timed := helper.SampleValue(mustSamples(f, surface), metricDurationCount, map[string]string{"k8s_verb": "watch"})
		Expect(timed).To(BeFalse(), "a watch must never enter the latency histogram")
	})

	It("keeps every label inside its documented set under arbitrary requests", func() {
		config := f.NewProxyRestConfig()
		client := &http.Client{Transport: config.Transport}
		for i := 0; i < 30; i++ {
			req, err := http.NewRequest(fmt.Sprintf("M%d", i), fmt.Sprintf("%s/apis/g%d/v1/r%d/n%d", config.Host, i, i, i), nil)
			Expect(err).NotTo(HaveOccurred())
			resp, err := client.Do(req)
			Expect(err).NotTo(HaveOccurred())
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		Eventually(func() (int, error) {
			ss, err := samples(f, surface)
			if err != nil {
				return 0, err
			}
			return len(helper.LabelValuesOf(ss, metricRequestsTotal, "k8s_verb")), nil
		}, 20*time.Second, time.Second).Should(BeNumerically(">=", 1))

		samples := mustSamples(f, surface)
		for _, v := range helper.LabelValuesOf(samples, metricRequestsTotal, "k8s_verb") {
			Expect(knownVerbs).To(HaveKey(v), "k8s_verb leaked %q", v)
		}
		for _, v := range helper.LabelValuesOf(samples, metricRequestsTotal, "scope") {
			Expect(knownScopes).To(HaveKey(v), "scope leaked %q", v)
		}
		for _, s := range samples {
			for k, v := range s.Labels {
				Expect(v).NotTo(ContainSubstring("/"), "label %s carries a path: %q", k, v)
				Expect(v).NotTo(ContainSubstring("@"), "label %s carries an identity: %q", k, v)
			}
		}
	})
})

// metricsServiceName mirrors the chart's <fullname>-metrics naming for the
// suite's own Deployment name.
func metricsServiceName() string { return kind.ProxyImageName + "-metrics" }

// scrapeRaw reads /metrics through the API server's Service proxy, so the
// suite needs no in-cluster pod and no NodePort: the kind API server reaches
// the pod IP directly. It returns the transport error rather than asserting,
// so callers inside Eventually can retry on it.
func scrapeRaw(ctx context.Context, f *framework.Framework, s helper.ChartMetricsSurface) ([]byte, error) {
	return f.Helper().KubeClient.CoreV1().RESTClient().Get().
		Namespace(f.Namespace.Name).
		Resource("services").
		Name(fmt.Sprintf("%s:%s", metricsServiceName(), s.PortName)).
		SubResource("proxy").
		Suffix("metrics").
		DoRaw(ctx)
}

// samples scrapes and parses; errors are returned for Eventually to retry on.
func samples(f *framework.Framework, s helper.ChartMetricsSurface) ([]helper.Sample, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := scrapeRaw(ctx, f, s)
	if err != nil {
		return nil, err
	}
	return helper.ParseMetrics(string(raw))
}

// mustSamples is samples for a direct assertion outside Eventually.
func mustSamples(f *framework.Framework, s helper.ChartMetricsSurface) []helper.Sample {
	ss, err := samples(f, s)
	Expect(err).NotTo(HaveOccurred(), "scraping through the Service proxy")
	return ss
}

// sampleValue is the polled form: a scrape error fails the attempt, an
// absent sample reads as 0.
func sampleValue(f *framework.Framework, s helper.ChartMetricsSurface, name string, labels map[string]string) (float64, error) {
	ss, err := samples(f, s)
	if err != nil {
		return 0, err
	}
	v, _ := helper.SampleValue(ss, name, labels)
	return v, nil
}

func validToken(f *framework.Framework) string {
	payload, err := f.Helper().NewTokenPayloadForIdentity(f.IssuerURL(), f.ClientID(),
		defaultUsername, []string{"group-1"}, time.Now().Add(10*time.Minute))
	Expect(err).NotTo(HaveOccurred())
	signed, err := f.Helper().SignToken(f.IssuerKeyBundle(), payload)
	Expect(err).NotTo(HaveOccurred())
	return signed
}

func doRequest(f *framework.Framework, token string) *http.Response {
	config := f.NewProxyRestConfig()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/namespaces/%s/pods", config.Host, f.Namespace.Name), nil)
	Expect(err).NotTo(HaveOccurred())
	req.Header.Set("Authorization", "bearer "+token)
	resp, err := (&http.Client{Transport: config.Transport}).Do(req)
	Expect(err).NotTo(HaveOccurred())
	_, _ = io.Copy(io.Discard, resp.Body)
	Expect(resp.Body.Close()).To(Succeed())
	return resp
}

func grantPods(f *framework.Framework, username string, verbs ...string) {
	role, err := f.Helper().KubeClient.RbacV1().Roles(f.Namespace.Name).Create(context.TODO(), &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "metrics-pods-"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: verbs}},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
	_, err = f.Helper().KubeClient.RbacV1().RoleBindings(f.Namespace.Name).Create(context.TODO(), &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "metrics-pods-"},
		Subjects:   []rbacv1.Subject{{Name: username, Kind: "User"}},
		RoleRef:    rbacv1.RoleRef{Name: role.Name, Kind: "Role"},
	}, metav1.CreateOptions{})
	Expect(err).NotTo(HaveOccurred())
}
