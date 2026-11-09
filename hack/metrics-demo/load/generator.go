// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/rafpe/kube-oidc-proxy/internal/devkit/idtoken"
	"github.com/rafpe/kube-oidc-proxy/internal/devkit/promtext"
)

type generator struct {
	logger    *slog.Logger
	st        *state
	cluster   kubernetes.Interface
	namespace string
	tunnel    *tunnel
	pinned    *pinnedPod
	client    *http.Client
}

// pinnedPod is one replica addressed directly, together with its own /metrics.
// A counter only moves on the replica that served the call, and the Service
// spreads calls over both replicas, so a scenario that asserts "this counter
// grew by exactly N" has to send its N calls to one pod and read that pod's
// exposition. It also makes the coalescing floor exactly one review rather
// than one per replica.
type pinnedPod struct {
	name    string
	proxy   *tunnel
	metrics *tunnel
}

func (p *pinnedPod) Close() {
	if p == nil {
		return
	}
	p.proxy.Close()
	p.metrics.Close()
}

// pin picks a ready proxy pod and opens a forward to its proxy port and to the
// metrics port it declares by name.
func (g *generator) pin(ctx context.Context, logger *slog.Logger) (*pinnedPod, error) {
	pods, err := g.cluster.CoreV1().Pods(g.namespace).List(ctx, metav1.ListOptions{LabelSelector: proxyPodSelector})
	if err != nil {
		return nil, fmt.Errorf("failed to list the proxy pods in %s: %w", g.namespace, err)
	}

	var pod *corev1.Pod
	for i := range pods.Items {
		if pods.Items[i].Status.Phase == corev1.PodRunning {
			pod = &pods.Items[i]

			break
		}
	}
	if pod == nil {
		return nil, fmt.Errorf("no running proxy pod in %s matching %s", g.namespace, proxyPodSelector)
	}

	metricsPort := int32(0)
	for _, c := range pod.Spec.Containers {
		for _, port := range c.Ports {
			if port.Name == metricsPortName {
				metricsPort = port.ContainerPort
			}
		}
	}
	if metricsPort == 0 {
		return nil, fmt.Errorf("pod %s declares no container port named %q; is metrics.enabled set?", pod.Name, metricsPortName)
	}

	proxyTun, err := newTunnel(ctx, g.st.kubeconfig, g.namespace, "pod/"+pod.Name, proxyPodPort, "https", logger)
	if err != nil {
		return nil, err
	}
	metricsTun, err := newTunnel(ctx, g.st.kubeconfig, g.namespace, "pod/"+pod.Name, int(metricsPort), "http", logger)
	if err != nil {
		proxyTun.Close()

		return nil, err
	}

	return &pinnedPod{name: pod.Name, proxy: proxyTun, metrics: metricsTun}, nil
}

// scrape reads the pinned replica's exposition.
func (g *generator) scrape(ctx context.Context) ([]promtext.Sample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.pinned.metrics.URL()+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to scrape %s: %w", g.pinned.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scraping %s answered %d", g.pinned.name, resp.StatusCode)
	}

	return promtext.Parse(string(body))
}

// sarMissLabels selects the SAR decision cache's misses. A fresh literal on
// every call, so nothing package-level is mutable.
func sarMissLabels() map[string]string { return map[string]string{"cache": "sar", "result": "miss"} }

// seriesSum totals every series of name whose labels include the given pairs,
// which is what a delta assertion needs: promtext.SampleValue answers with the
// first matching series only, and a denial reason or a review outcome is
// spread over several.
func seriesSum(samples []promtext.Sample, name string, labels map[string]string) float64 {
	var total float64
	for _, s := range samples {
		if s.Name != name {
			continue
		}
		matched := true
		for k, v := range labels {
			if s.Labels[k] != v {
				matched = false

				break
			}
		}
		if matched {
			total += s.Value
		}
	}

	return total
}

func newGenerator(logger *slog.Logger, st *state, namespace string, tun *tunnel) (*generator, error) {
	restConfig, err := clientcmd.BuildConfigFromFlags("", st.kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build a rest config from %q: %w", st.kubeconfig, err)
	}
	cluster, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build a kubernetes client: %w", err)
	}

	return &generator{
		logger:    logger,
		st:        st,
		cluster:   cluster,
		namespace: namespace,
		tunnel:    tun,
		client: &http.Client{
			Timeout: callTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: st.proxyCAs, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

// token mints an OIDC token for an identity the demo issuer will vouch for.
func (g *generator) token(username string, groups []string, exp time.Time) (string, error) {
	payload := idtoken.NewPayloadForIdentity(g.st.issuerURL, demoClientID, username, groups, exp)

	return idtoken.Sign(g.st.issuerBundle, payload)
}

func (g *generator) validToken() (string, error) {
	return g.token(demoUser, []string{"demo"}, time.Now().Add(10*time.Minute))
}

// tokenWithoutUsername mints a token the demo issuer signs and the proxy
// accepts, whose username claim is present but empty.
func (g *generator) tokenWithoutUsername(exp time.Time) (string, error) {
	return g.token("", []string{"demo"}, exp)
}

// restConfig points client-go at the proxy with a bearer token, verifying the
// serving certificate against the CA the demo minted it with. The proxy's
// certificate carries 127.0.0.1 in its IP SANs, so no verification is skipped
// and no server name is overridden.
func (g *generator) restConfig(token string) *rest.Config {
	return &rest.Config{
		Host:            g.tunnel.URL(),
		BearerToken:     token,
		TLSClientConfig: rest.TLSClientConfig{CAData: g.st.proxyCAPEM},
	}
}

// do issues one request against the proxy through the Service and returns its
// status code.
func (g *generator) do(ctx context.Context, method, path, token string, headers http.Header) (int, error) {
	return g.doAt(ctx, g.tunnel.URL(), method, path, token, headers)
}

// doAt is do against one specific address, so a scenario that reads a replica's
// own counters can be sure the calls it is measuring reached that replica.
func (g *generator) doAt(ctx context.Context, base, method, path, token string, headers http.Header) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, base+path, nil)
	if err != nil {
		return 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	return resp.StatusCode, nil
}

func (g *generator) doWithValidToken(ctx context.Context, method, path string, headers http.Header) (int, error) {
	token, err := g.validToken()
	if err != nil {
		return 0, err
	}

	return g.do(ctx, method, path, token, headers)
}

// serviceAccountToken mints a short-lived token for the demo ServiceAccount
// through the TokenRequest API. The proxy cannot verify it as an OIDC token,
// so it falls back to a TokenReview against the API server.
func (g *generator) serviceAccountToken(ctx context.Context) (string, error) {
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: ptr(int64(600))},
	}
	tr, err := g.cluster.CoreV1().ServiceAccounts(g.namespace).
		CreateToken(ctx, demoSA, req, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to mint a token for serviceaccount %s/%s: %w", g.namespace, demoSA, err)
	}

	return tr.Status.Token, nil
}

// unknownServiceAccountToken is a bearer token no issuer will vouch for. The
// proxy answers the client 401, but the TokenReview behind it does not come
// back as a plain rejection: kube-apiserver (v1.37.0, measured against this
// demo) sets status.error "invalid bearer token" for every token no
// authenticator claims - a JWT-shaped one with a bad signature, an opaque
// random string, anything - so the proxy records
// authentication_attempts_total{tokenreview,error} and
// review_requests_total{tokenreview,error}. That is deliberate here: it is
// the only traffic in the demo that lights the security dashboard's
// TokenReview error panels, and it is why they are not flat zero in the
// screenshots. There is no token shape that produces
// {tokenreview,rejected} against this API server.
func unknownServiceAccountToken() string {
	return "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlbW8ifQ." +
		"eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cHJveHk6bm9ib2R5In0." +
		"bm90LWEtdmFsaWQtc2lnbmF0dXJl"
}

func ptr[T any](v T) *T { return &v }
