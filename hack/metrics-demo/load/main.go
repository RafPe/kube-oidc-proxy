// Copyright Jetstack Ltd. See LICENSE for details.

// Command load drives every kind of traffic the metric catalogue can observe
// through the demo proxy, so that every dashboard panel has something to draw.
// One scenario per metric family or label value: allowed and forbidden
// requests, invalid and expired tokens, allowed and denied impersonation, the
// two anomaly denials, both token-passthrough outcomes, a watch, an exec, a
// log stream, non-resource paths and requests with verbs that are not
// Kubernetes verbs at all.
//
// With --once each scenario runs exactly once and the program exits non-zero
// if any call did not produce its expected status; that is this task's test.
// With --duration it rotates through them until the time is up.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"

	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/config"
	"github.com/rafpe/kube-oidc-proxy/test/e2e/framework/helper"
	"github.com/rafpe/kube-oidc-proxy/test/util"
)

const (
	// The identity the demo's OIDC tokens carry, and the one the demo RBAC
	// grants; see hack/metrics-demo/demo-identities.yaml.
	demoUser      = "user@example.com"
	demoClientID  = "kube-oidc-proxy"
	demoPod       = "demo-shell"
	demoSA        = "demo-passthrough"
	impersonated  = "jjackson"
	notImpersonat = "mallory"

	// cacheWarmCalls is how many identical calls a cache-exercising scenario
	// makes. The proxy runs two replicas behind a ClusterIP, each with its own
	// cache, so three identical calls guarantee at least one lands on a
	// replica that has already cached the decision.
	cacheWarmCalls = 3

	// coalesceCalls is how many identical impersonation calls the coalescing
	// scenario fires at one replica at once. More than a handful and the
	// assertion stops being about coalescing and starts being about the
	// client's own concurrency; fewer and a single accidental serialisation
	// would satisfy "fewer reviews than calls" on its own.
	coalesceCalls = 8

	// sarCacheTTL is pkg/proxy/subjectaccessreview.DefaultAllowCacheTTL, which
	// the chart does not override in the demo. The coalescing scenario waits
	// this out so the replica it addresses answers from a genuinely cold
	// cache; without the wait it would measure the cache, not the flight
	// group. Not imported, so this program stays a client of the deployed
	// proxy rather than of the package it was built from.
	sarCacheTTL = 10 * time.Second

	// The proxy Service and the container ports the chart renders
	// (chart/kube-oidc-proxy/templates/deployment.yaml). The metrics port is
	// the only named one, so it is looked up by name and never assumed.
	proxyService      = "svc/kop-kube-oidc-proxy"
	proxyServicePort  = 443
	proxyPodPort      = 8443
	metricsPortName   = "metrics"
	proxyPodSelector  = "app.kubernetes.io/name=kube-oidc-proxy,app.kubernetes.io/instance=kop"
	metricDecisions   = "kube_oidc_proxy_access_decisions_total"
	metricReviewCalls = "kube_oidc_proxy_review_requests_total"

	// statusNone marks a scenario that completes without an HTTP status the
	// client can observe, because the connection was upgraded or streamed.
	statusNone = 0

	// hostileMethodCount is how many non-Kubernetes methods the hostile
	// scenario sends, and hostileMethodStatus what each must answer with:
	// observed against the demo cluster, not assumed. The proxy authenticates
	// the token and impersonates, and the API server then refuses a verb its
	// RBAC has no rule for.
	hostileMethodCount  = 9
	hostileMethodStatus = http.StatusForbidden

	// noUsernameClaimStatus is what the proxy answers a token that carries no
	// username: the identity authenticated but names nobody, so there is
	// nobody to impersonate. Not 401 - the token itself was accepted.
	noUsernameClaimStatus = http.StatusForbidden

	// How many times the tunnel tries to come back after kubectl drops it.
	tunnelReopenAttempts = 10

	watchHold  = 20 * time.Second
	callTimout = 30 * time.Second
)

func main() {
	opts := struct {
		state     string
		namespace string
		duration  time.Duration
		interval  time.Duration
		once      bool
	}{}
	flag.StringVar(&opts.state, "state", "hack/metrics-demo/.state", "directory up.sh wrote the demo's kubeconfig and key material to")
	flag.StringVar(&opts.namespace, "namespace", "proxy", "namespace the proxy and the demo workload run in")
	flag.DurationVar(&opts.duration, "duration", 10*time.Minute, "how long to keep generating traffic")
	flag.DurationVar(&opts.interval, "interval", 500*time.Millisecond, "pause between calls")
	flag.BoolVar(&opts.once, "once", false, "run each scenario exactly once and assert its expected status")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger, opts.state, opts.namespace, opts.duration, opts.interval, opts.once); err != nil {
		logger.Error("load generator failed", slog.String("error_message", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger, statePath, namespace string, duration, interval time.Duration, once bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := loadState(statePath)
	if err != nil {
		return err
	}

	tun, err := newTunnel(ctx, st.kubeconfig, namespace, proxyService, proxyServicePort, "https", logger)
	if err != nil {
		return err
	}
	defer tun.Close()

	g, err := newGenerator(st, namespace, tun)
	if err != nil {
		return err
	}

	// The scenarios that assert on how far a counter moved need one replica
	// they can address directly, and that replica's own /metrics.
	pin, err := g.pin(ctx, logger)
	if err != nil {
		return err
	}
	defer pin.Close()
	g.pinned = pin

	scenarios := g.scenarios()

	if once {
		return g.runOnce(ctx, logger, scenarios)
	}

	return g.runFor(ctx, logger, scenarios, duration, interval)
}

// state is what up.sh left in .state: the kubeconfig, the issuer's URL and
// signing key, and the certificate that issued the proxy's serving cert.
type state struct {
	kubeconfig   string
	issuerURL    *url.URL
	issuerBundle *util.KeyBundle
	proxyCAs     *x509.CertPool
	proxyCAPEM   []byte
}

func loadState(dir string) (*state, error) {
	read := func(name string) ([]byte, error) {
		// #nosec G304 -- dir is the operator's own --state flag, and every
		// name is a constant below; this is a developer tool reading the
		// files up.sh just wrote.
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s from %s; run 'make metrics_demo_up' first: %s", name, dir, err)
		}

		return b, nil
	}

	rawURL, err := read("issuer-url")
	if err != nil {
		return nil, err
	}
	issuerURL, err := url.Parse(strings.TrimSpace(string(rawURL)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse issuer-url: %s", err)
	}

	certBytes, err := read("issuer-ca.pem")
	if err != nil {
		return nil, err
	}
	keyBytes, err := read("issuer-key.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, errors.New("issuer-key.pem is not PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the issuer key: %s", err)
	}

	proxyCA, err := read("proxy-ca.pem")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(proxyCA) {
		return nil, errors.New("proxy-ca.pem holds no certificate")
	}

	return &state{
		kubeconfig:   filepath.Join(dir, "kubeconfig"),
		issuerURL:    issuerURL,
		issuerBundle: &util.KeyBundle{CertBytes: certBytes, KeyBytes: keyBytes, Key: key},
		proxyCAs:     pool,
		proxyCAPEM:   proxyCA,
	}, nil
}

// portForward opens a tunnel to the proxy Service and returns the local port
// kubectl chose for it. The port is not fixed: a hard-coded one silently
// attaches this run to a forward left behind by a previous one, which then
// dies under it and turns every call into "connection refused". kubectl
// announces the port it picked on stdout, and that line is also the signal
// that the tunnel is ready, so nothing has to poll for it.
// tunnel keeps a kubectl port-forward to the proxy Service open for the life
// of the run. kubectl drops a forward when a client disappears mid-stream
// ("lost connection to pod" after a broken pipe), and this generator does that
// on purpose in the exec and watch scenarios, so the tunnel reopens itself
// instead of turning the rest of the run into "connection refused". The local
// port is whatever kubectl picks, and changes when it reopens: a fixed port
// would silently attach to a forward left behind by an earlier run.
type tunnel struct {
	kubeconfig string
	namespace  string
	target     string
	remote     int
	scheme     string
	logger     *slog.Logger

	mu     sync.Mutex
	port   int
	stop   func()
	closed bool
}

func newTunnel(ctx context.Context, kubeconfig, namespace, target string, remote int, scheme string, logger *slog.Logger) (*tunnel, error) {
	t := &tunnel{
		kubeconfig: kubeconfig,
		namespace:  namespace,
		target:     target,
		remote:     remote,
		scheme:     scheme,
		logger:     logger,
	}
	if err := t.open(ctx); err != nil {
		return nil, err
	}

	return t, nil
}

// URL is the far end's address through the tunnel as it stands right now.
func (t *tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return fmt.Sprintf("%s://127.0.0.1:%d", t.scheme, t.port)
}

func (t *tunnel) Close() {
	t.mu.Lock()
	t.closed = true
	stop := t.stop
	t.mu.Unlock()

	if stop != nil {
		stop()
	}
}

func (t *tunnel) open(ctx context.Context) error {
	port, stop, err := startPortForward(ctx, t.kubeconfig, t.namespace, t.target, t.remote, func(cause error) {
		t.reopen(ctx, cause)
	})
	if err != nil {
		return err
	}

	t.mu.Lock()
	t.port, t.stop = port, stop
	t.mu.Unlock()

	return nil
}

func (t *tunnel) reopen(ctx context.Context, cause error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return
	}

	t.logger.Warn("port-forward dropped, reopening",
		slog.String("target", t.target),
		slog.String("error_message", cause.Error()))

	for i := 0; i < tunnelReopenAttempts; i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		if err := t.open(ctx); err == nil {
			t.logger.Info("port-forward reopened",
				slog.String("target", t.target), slog.String("url", t.URL()))

			return
		}
	}

	t.logger.Error("port-forward could not be reopened; traffic has stopped",
		slog.String("target", t.target))
}

// startPortForward runs one kubectl port-forward and returns the local port it
// chose. onDeath is called if it exits on its own.
func startPortForward(ctx context.Context, kubeconfig, namespace, target string, remote int, onDeath func(error)) (int, func(), error) {
	// #nosec G204 -- the binary is the constant "kubectl"; the variable
	// arguments are the operator's own --state and --namespace flags and a
	// target this program composed from names it read out of the cluster.
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", namespace,
		"port-forward", target, fmt.Sprintf(":%d", remote))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, nil, err
	}
	stderr := &strings.Builder{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return 0, nil, fmt.Errorf("failed to start kubectl port-forward: %s", err)
	}

	port, err := readForwardedPort(stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()

		return 0, nil, fmt.Errorf("%s: %s", err, strings.TrimSpace(stderr.String()))
	}

	// kubectl keeps writing a line per connection. Nothing reads them, so the
	// pipe must be drained or kubectl blocks on a full buffer once the run has
	// made a few hundred calls, and the traffic simply stops.
	go func() { _, _ = io.Copy(io.Discard, stdout) }()

	// Exactly one goroutine may Wait on a command, so this one owns it and
	// stop() waits for it rather than calling Wait itself.
	stopping := make(chan struct{})
	waited := make(chan struct{})
	go func() {
		defer close(waited)
		err := cmd.Wait()
		select {
		case <-stopping: // stop() killed it; expected.
		default:
			onDeath(fmt.Errorf("kubectl port-forward exited (%v): %s",
				err, strings.TrimSpace(stderr.String())))
		}
	}()

	stop := func() {
		close(stopping)
		_ = cmd.Process.Kill()
		<-waited
	}

	return port, stop, nil
}

// forwardedPort matches kubectl's "Forwarding from 127.0.0.1:54321 -> 8443".
var forwardedPort = regexp.MustCompile(`^Forwarding from 127\.0\.0\.1:(\d+) ->`)

func readForwardedPort(stdout io.Reader) (int, error) {
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		m := forwardedPort.FindStringSubmatch(scanner.Text())
		if m == nil {
			continue
		}

		return strconv.Atoi(m[1])
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("failed to read kubectl port-forward output: %s", err)
	}

	return 0, errors.New("kubectl port-forward exited before it announced a local port")
}

type generator struct {
	st        *state
	helper    *helper.Helper
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
		return nil, fmt.Errorf("failed to list the proxy pods in %s: %s", g.namespace, err)
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
func (g *generator) scrape(ctx context.Context) ([]helper.Sample, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.pinned.metrics.URL()+"/metrics", nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to scrape %s: %s", g.pinned.name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scraping %s answered %d", g.pinned.name, resp.StatusCode)
	}

	return helper.ParseMetrics(string(body))
}

// seriesSum totals every series of name whose labels include the given pairs,
// which is what a delta assertion needs: helper.SampleValue answers with the
// first matching series only, and a denial reason or a review outcome is
// spread over several.
func seriesSum(samples []helper.Sample, name string, labels map[string]string) float64 {
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

func newGenerator(st *state, namespace string, tun *tunnel) (*generator, error) {
	restConfig, err := clientcmd.BuildConfigFromFlags("", st.kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build a rest config from %q: %s", st.kubeconfig, err)
	}
	cluster, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build a kubernetes client: %s", err)
	}

	h := helper.NewHelper(&config.Config{KubeConfigPath: st.kubeconfig, RepoRoot: "."})
	h.KubeClient = cluster

	return &generator{
		st:        st,
		helper:    h,
		cluster:   cluster,
		namespace: namespace,
		tunnel:    tun,
		client: &http.Client{
			Timeout: callTimout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: st.proxyCAs, MinVersion: tls.VersionTLS12},
			},
		},
	}, nil
}

// token mints an OIDC token for an identity the demo issuer will vouch for.
func (g *generator) token(username string, groups []string, exp time.Time) (string, error) {
	payload, err := g.helper.NewTokenPayloadForIdentity(g.st.issuerURL, demoClientID, username, groups, exp)
	if err != nil {
		return "", err
	}

	return g.helper.SignToken(g.st.issuerBundle, payload)
}

func (g *generator) validToken() (string, error) {
	return g.token(demoUser, []string{"demo"}, time.Now().Add(10*time.Minute))
}

// tokenWithoutUsername mints a token the demo issuer signs and the proxy
// accepts, whose username claim is empty. helper.NewTokenPayloadForIdentity
// always writes an "email", so the payload is built here instead.
func (g *generator) tokenWithoutUsername(exp time.Time) (string, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"iss":    g.st.issuerURL.String(),
		"aud":    []string{demoClientID, "aud-2"},
		"email":  "",
		"groups": []string{"demo"},
		"exp":    exp.Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal the token payload: %s", err)
	}

	return g.helper.SignToken(g.st.issuerBundle, payload)
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

// result is one HTTP exchange: what it was, what came back, and what was
// expected. A scenario reports one per constituent call rather than one for
// itself, so --once asserts every call it makes and the log carries a record
// per call instead of per scenario: a scenario whose first eight calls failed
// and whose ninth succeeded used to report success.
//
// want is the status the proxy or the API server must answer with; statusNone
// means the exchange finishes without one, because the connection was upgraded
// or the body was streamed.
type result struct {
	kind     string
	want     int
	status   int
	duration time.Duration
	err      error
}

func (r result) ok() bool { return r.err == nil && r.status == r.want }

// scenario is one kind of traffic, made of one or more calls.
type scenario struct {
	name string
	run  func(context.Context) []result
}

// observe runs one call and times it. The error is carried in the result
// rather than returned, so a scenario reports every call it made even when an
// early one failed.
func (g *generator) observe(ctx context.Context, kind string, want int, run func(context.Context) (int, error)) result {
	start := time.Now()
	status, err := run(ctx)

	return result{kind: kind, want: want, status: status, duration: time.Since(start), err: err}
}

// one builds a scenario that is a single call.
func (g *generator) one(name string, want int, run func(context.Context) (int, error)) scenario {
	return scenario{name: name, run: func(ctx context.Context) []result {
		return []result{g.observe(ctx, name, want, run)}
	}}
}

// failed builds the single result that stands for a scenario whose setup — a
// token to mint, a pod to find — did not get as far as a call.
func failed(kind string, err error) []result {
	return []result{{kind: kind, err: err}}
}

func (g *generator) scenarios() []scenario {
	pods := fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace)

	return []scenario{
		// requests_total{list,namespace,200}, the duration histogram,
		// authentication_attempts_total{oidc,accepted}, decisions{allow}.
		g.one("allowed_list", http.StatusOK, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods, nil)
		}),
		// The same, at resource scope rather than namespace scope.
		g.one("allowed_get", http.StatusOK, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods+"/"+demoPod, nil)
		}),
		// The proxy allows the request; the API server refuses the
		// impersonated identity. A 403 that is not a proxy denial.
		g.one("forbidden_by_rbac", http.StatusForbidden, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, "/api/v1/nodes", nil)
		}),
		// A 5xx from the upstream, provoked without any fault injection: a
		// list at a resource version the API server will never observe is
		// answered "Too large resource version" with 504 after it gives up
		// waiting. It is the API server's own answer, so the proxy's exchange
		// completed normally - this is what puts a 5xx band on "Responses by
		// code class", not what puts a line on "Upstream failures/s", which
		// counts requests the hop to the API server never completed at all.
		g.one("upstream_5xx", http.StatusGatewayTimeout, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet,
				pods+"?resourceVersion=99999999999&timeoutSeconds=2", nil)
		}),
		// Not a JWT at all: rejected by OIDC, then by the TokenReview
		// fallback. decisions{deny,unauthorized}.
		g.one("invalid_token", http.StatusUnauthorized, func(ctx context.Context) (int, error) {
			return g.do(ctx, http.MethodGet, pods, "not-a-token-"+time.Now().Format(time.RFC3339Nano), nil)
		}),
		// Correctly signed, but past its exp: the same outcome by a
		// different route through the authenticator.
		g.one("expired_token", http.StatusUnauthorized, func(ctx context.Context) (int, error) {
			token, err := g.token(demoUser, []string{"demo"}, time.Now().Add(-time.Hour))
			if err != nil {
				return 0, err
			}

			return g.do(ctx, http.MethodGet, pods, token, nil)
		}),
		// review_requests_total{sar,allow}, cache_lookups_total (a miss,
		// then hits on every later run), decisions{allow}.
		{name: "impersonation_allowed", run: func(ctx context.Context) []result {
			// Three times, back to back: the first call to each replica is a
			// cache miss and issues a real SubjectAccessReview, and with two
			// replicas a third call is guaranteed to land on one that is
			// already warm. One call on its own would only ever produce
			// misses, because the rotation comes round again long after the
			// cache entry has expired.
			headers := http.Header{"Impersonate-User": []string{impersonated}}

			return g.repeat(ctx, "impersonation_allowed", cacheWarmCalls, http.StatusOK,
				func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, pods, headers)
				})
		}},
		// The flight group: identical impersonation calls that arrive at one
		// replica while its cache is cold share a single SubjectAccessReview.
		{name: "impersonation_coalesced", run: g.coalescedImpersonation},
		// review_requests_total{sar,deny},
		// decisions{deny,impersonation_denied}.
		g.one("impersonation_denied", http.StatusForbidden, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods,
				http.Header{"Impersonate-User": []string{notImpersonat}})
		}),
		// decisions{deny,too_many_impersonation_values}: refused on the
		// header count before any review is issued.
		g.one("too_many_impersonation_values", http.StatusRequestHeaderFieldsTooLarge, func(ctx context.Context) (int, error) {
			headers := http.Header{"Impersonate-User": []string{impersonated}}
			for i := 0; i < 100; i++ {
				headers.Add("Impersonate-Group", fmt.Sprintf("group-%d", i))
			}

			return g.doWithValidToken(ctx, http.MethodGet, pods, headers)
		}),
		// decisions{deny,reserved_identity}: a token claiming a group the
		// proxy will never impersonate.
		g.one("reserved_identity", http.StatusForbidden, func(ctx context.Context) (int, error) {
			token, err := g.token(demoUser, []string{"system:masters"}, time.Now().Add(10*time.Minute))
			if err != nil {
				return 0, err
			}

			return g.do(ctx, http.MethodGet, pods, token, nil)
		}),
		// decisions{deny,no_username_claim}: a token the issuer vouches for
		// that names nobody.
		{name: "no_username_claim", run: g.noUsernameClaim},
		// authentication_attempts_total{oidc,rejected} then
		// {tokenreview,accepted}, review_requests_total{tokenreview,allow}.
		{name: "passthrough_allowed", run: func(ctx context.Context) []result {
			token, err := g.serviceAccountToken(ctx)
			if err != nil {
				return failed("passthrough_allowed", err)
			}

			// The same token repeatedly, so the TokenReview result is cached
			// and reused rather than reviewed again on every call. A freshly
			// minted token on each call would only ever miss.
			return g.repeat(ctx, "passthrough_allowed", cacheWarmCalls, http.StatusOK,
				func(ctx context.Context) (int, error) {
					return g.do(ctx, http.MethodGet, pods, token, nil)
				})
		}},
		// A token the API server cannot authenticate either:
		// authentication_attempts_total{tokenreview,rejected}.
		{name: "passthrough_denied", run: func(ctx context.Context) []result {
			// Repeated with the same token, so a later lookup is served from
			// the TokenReview failure cache rather than reviewed again; that
			// is what shields the API server from a client retrying a bad
			// token in a loop.
			return g.repeat(ctx, "passthrough_denied", cacheWarmCalls, http.StatusUnauthorized,
				func(ctx context.Context) (int, error) {
					return g.do(ctx, http.MethodGet, pods, unknownServiceAccountToken(), nil)
				})
		}},
		// long_running_requests{watch}, released when the client goes away:
		// termination client_cancel.
		g.one("watch", statusNone, g.watch),
		// The hijack path: long_running_requests{connect}, termination
		// hijacked, code none.
		g.one("exec", statusNone, g.exec),
		// A streamed response that is long-running but not hijacked.
		g.one("logs", http.StatusOK, func(ctx context.Context) (int, error) {
			return g.doWithValidToken(ctx, http.MethodGet, pods+"/"+demoPod+"/log", nil)
		}),
		// scope none, verb get: paths with no RequestInfo resource. Both are
		// asserted; the /version status used to be discarded because only the
		// last call of a scenario was checked.
		{name: "non_resource", run: func(ctx context.Context) []result {
			return []result{
				g.observe(ctx, "non_resource[/version]", http.StatusOK, func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, "/version", nil)
				}),
				g.observe(ctx, "non_resource[/healthz]", http.StatusOK, func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, "/healthz", nil)
				}),
			}
		}},
		// Verbs that are not HTTP methods and not Kubernetes verbs: every one
		// must land on k8s_verb="other", scope="none", and never create a new
		// series.
		{name: "hostile_methods", run: g.hostileMethods},
	}
}

// noUsernameClaim sends a token the issuer signed that carries no username in
// the claim the proxy maps identities from, and asserts that the replica it
// went to counted the denial under that reason rather than under a generic
// one. Without the counter check the scenario would only prove that some
// denial happened.
func (g *generator) noUsernameClaim(ctx context.Context) []result {
	token, err := g.tokenWithoutUsername(time.Now().Add(10 * time.Minute))
	if err != nil {
		return failed("no_username_claim", err)
	}

	before, err := g.scrape(ctx)
	if err != nil {
		return failed("no_username_claim", err)
	}

	r := g.observe(ctx, "no_username_claim", noUsernameClaimStatus, func(ctx context.Context) (int, error) {
		return g.doAt(ctx, g.pinned.proxy.URL(), http.MethodGet,
			fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace), token, nil)
	})
	if r.err != nil {
		return []result{r}
	}

	after, err := g.scrape(ctx)
	if err != nil {
		r.err = err

		return []result{r}
	}

	labels := map[string]string{"decision": "deny", "reason": "no_username_claim"}
	grew := seriesSum(after, metricDecisions, labels) - seriesSum(before, metricDecisions, labels)
	if grew < 1 {
		r.err = fmt.Errorf("%s recorded no decisions{reason=no_username_claim} for the call (delta %.0f)",
			g.pinned.name, grew)
	}

	return []result{r}
}

// coalescedImpersonation fires coalesceCalls identical impersonation requests
// at one replica whose decision cache has just expired, and asserts that they
// shared SubjectAccessReviews: every call must be allowed, and the replica
// must have issued fewer reviews than it answered calls. This is the property
// that keeps a thundering herd of clients from becoming a thundering herd of
// SubjectAccessReviews against the API server.
func (g *generator) coalescedImpersonation(ctx context.Context) []result {
	token, err := g.validToken()
	if err != nil {
		return failed("impersonation_coalesced", err)
	}

	// The cache is what would otherwise answer these calls, and a cached
	// decision issues no review at all, which would satisfy "fewer reviews
	// than calls" without proving anything about coalescing.
	select {
	case <-ctx.Done():
		return failed("impersonation_coalesced", ctx.Err())
	case <-time.After(sarCacheTTL + time.Second):
	}

	before, err := g.scrape(ctx)
	if err != nil {
		return failed("impersonation_coalesced", err)
	}

	headers := http.Header{"Impersonate-User": []string{impersonated}}
	// One slot per call, written only by the goroutine that owns it, so the
	// results stay in call order and nothing is shared but the slice header.
	results := make([]result, coalesceCalls)
	var wg sync.WaitGroup
	for i := 0; i < coalesceCalls; i++ {
		wg.Go(func() {
			results[i] = g.observe(ctx, fmt.Sprintf("impersonation_coalesced[%d/%d]", i+1, coalesceCalls),
				http.StatusOK, func(ctx context.Context) (int, error) {
					return g.doAt(ctx, g.pinned.proxy.URL(), http.MethodGet,
						fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace), token, headers)
				})
		})
	}
	wg.Wait()

	for _, r := range results {
		if !r.ok() {
			return results
		}
	}

	after, err := g.scrape(ctx)
	if err != nil {
		results[0].err = err

		return results
	}

	sar := map[string]string{"review": "sar"}
	allowed := map[string]string{"decision": "allow"}
	reviews := seriesSum(after, metricReviewCalls, sar) - seriesSum(before, metricReviewCalls, sar)
	decisions := seriesSum(after, metricDecisions, allowed) - seriesSum(before, metricDecisions, allowed)

	switch {
	case int(decisions) != coalesceCalls:
		results[0].err = fmt.Errorf("%s allowed %.0f of %d calls, want all of them",
			g.pinned.name, decisions, coalesceCalls)
	case reviews < 1:
		// Nothing was coalesced because nothing was reviewed: the cache was
		// still warm, and the assertion below would have passed for the wrong
		// reason.
		results[0].err = fmt.Errorf("%s issued no SubjectAccessReview at all; its decision cache had not expired",
			g.pinned.name)
	case int(reviews) >= coalesceCalls:
		results[0].err = fmt.Errorf("%s issued %.0f SubjectAccessReviews for %d simultaneous identical calls; they did not coalesce",
			g.pinned.name, reviews, coalesceCalls)
	}

	return results
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
		return "", fmt.Errorf("failed to mint a token for serviceaccount %s/%s: %s", g.namespace, demoSA, err)
	}

	return tr.Status.Token, nil
}

// unknownServiceAccountToken is a syntactically well-formed bearer token that
// no issuer will vouch for, so the TokenReview rejects rather than errors.
func unknownServiceAccountToken() string {
	return "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlbW8ifQ." +
		"eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6cHJveHk6bm9ib2R5In0." +
		"bm90LWEtdmFsaWQtc2lnbmF0dXJl"
}

func ptr[T any](v T) *T { return &v }

// watch holds a list-watch open, so the long-running gauge rises and then
// falls when the client cancels.
func (g *generator) watch(ctx context.Context) (int, error) {
	token, err := g.validToken()
	if err != nil {
		return 0, err
	}

	client, err := kubernetes.NewForConfig(g.restConfig(token))
	if err != nil {
		return 0, err
	}

	watchCtx, cancel := context.WithTimeout(ctx, watchHold)
	defer cancel()

	w, err := client.CoreV1().Pods(g.namespace).Watch(watchCtx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to open a watch: %s", err)
	}
	defer w.Stop()

	// Drain until the hold elapses; the point is the open connection, not
	// the events.
	for {
		select {
		case <-watchCtx.Done():
			return statusNone, nil
		case _, ok := <-w.ResultChan():
			if !ok {
				return statusNone, nil
			}
		}
	}
}

// exec runs a trivial command in the demo pod. The reverse proxy hijacks the
// connection before writing the 101, which is the case the recorder's onHijack
// hook exists for.
func (g *generator) exec(ctx context.Context) (int, error) {
	token, err := g.validToken()
	if err != nil {
		return 0, err
	}

	cfg := g.restConfig(token)
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return 0, err
	}

	req := client.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(g.namespace).Name(demoPod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "shell",
			Command:   []string{"true"},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(cfg, http.MethodPost, req.URL())
	if err != nil {
		return 0, fmt.Errorf("failed to build an exec executor: %s", err)
	}

	execCtx, cancel := context.WithTimeout(ctx, callTimout)
	defer cancel()

	if err := executor.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdout: io.Discard,
		Stderr: io.Discard,
	}); err != nil {
		return 0, fmt.Errorf("exec into %s/%s failed: %s", g.namespace, demoPod, err)
	}

	return statusNone, nil
}

// hostileMethods sends verbs no Kubernetes client uses. They must all be
// projected onto k8s_verb="other" rather than creating a series each. Each
// method is asserted and logged on its own: the scenario used to discard all
// nine statuses and report statusNone, so any of them could have been anything
// at all.
func (g *generator) hostileMethods(ctx context.Context) []result {
	token, err := g.validToken()
	if err != nil {
		return failed("hostile_methods", err)
	}

	out := make([]result, 0, hostileMethodCount)
	for i := 1; i <= hostileMethodCount; i++ {
		method := fmt.Sprintf("M%d", i)
		out = append(out, g.observe(ctx, "hostile_methods["+method+"]", hostileMethodStatus,
			func(ctx context.Context) (int, error) {
				return g.do(ctx, method, "/apis/x/v1/y", token, nil)
			}))
	}

	return out
}

// repeat runs the same call n times so a scenario can warm a cache and then
// hit it, and returns one result per call. It stops at the first call whose
// status diverged from want and names it: returning only the last status let a
// warm-up call fail unnoticed as long as the final one answered correctly.
func (g *generator) repeat(ctx context.Context, kind string, n, want int, call func(context.Context) (int, error)) []result {
	out := make([]result, 0, n)
	for i := 0; i < n; i++ {
		r := g.observe(ctx, fmt.Sprintf("%s[%d/%d]", kind, i+1, n), want, call)
		if r.err == nil && r.status != want {
			r.err = fmt.Errorf("call %d of %d answered %d, want %d", i+1, n, r.status, want)
		}
		out = append(out, r)
		if r.err != nil {
			return out
		}
	}

	return out
}

// runOnce runs every scenario once and fails if any of its calls produced an
// unexpected status. This is the test for the load generator itself.
func (g *generator) runOnce(ctx context.Context, logger *slog.Logger, scenarios []scenario) error {
	var failures []string
	calls := 0

	for _, s := range scenarios {
		for _, r := range g.call(ctx, logger, s) {
			calls++
			switch {
			case r.err != nil:
				failures = append(failures, fmt.Sprintf("%s: %s", r.kind, r.err))
			case r.status != r.want:
				failures = append(failures, fmt.Sprintf("%s: status %d, want %d", r.kind, r.status, r.want))
			}
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("%d of %d calls across %d scenarios did not behave as expected:\n  %s",
			len(failures), calls, len(scenarios), strings.Join(failures, "\n  "))
	}

	logger.Info("every call produced its expected status",
		slog.Int("scenarios", len(scenarios)), slog.Int("calls", calls))

	return nil
}

// runFor rotates through the scenarios until the duration is up, so every
// family keeps receiving traffic while the dashboards are watched.
func (g *generator) runFor(ctx context.Context, logger *slog.Logger, scenarios []scenario, duration, interval time.Duration) error {
	deadline := time.Now().Add(duration)
	for i := 0; time.Now().Before(deadline); i++ {
		s := scenarios[i%len(scenarios)]
		for _, r := range g.call(ctx, logger, s) {
			if r.err != nil {
				// A failure mid-run is traffic too: log it and keep going, so
				// a transient API server hiccup does not end a ten-minute run.
				logger.Warn("call failed", slog.String("kind", r.kind),
					slog.String("error_message", r.err.Error()))
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}

	logger.Info("load finished", slog.String("duration", duration.String()))

	return nil
}

// call runs one scenario and logs one record per call it made, so a reader can
// line the log up against the counters call by call rather than scenario by
// scenario.
func (g *generator) call(ctx context.Context, logger *slog.Logger, s scenario) []result {
	results := s.run(ctx)
	for _, r := range results {
		attrs := []any{
			slog.String("kind", r.kind),
			slog.Int("status", r.status),
			slog.Int64("duration_ms", r.duration.Milliseconds()),
			slog.Bool("ok", r.ok()),
		}
		if r.err != nil {
			attrs = append(attrs, slog.String("error_message", r.err.Error()))
		}
		logger.Info("call", attrs...)
	}

	return results
}
