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

	// statusNone marks a scenario that completes without an HTTP status the
	// client can observe, because the connection was upgraded or streamed.
	statusNone = 0

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

	tun, err := newTunnel(ctx, st.kubeconfig, namespace, logger)
	if err != nil {
		return err
	}
	defer tun.Close()

	g, err := newGenerator(st, namespace, tun)
	if err != nil {
		return err
	}

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
	logger     *slog.Logger

	mu     sync.Mutex
	port   int
	stop   func()
	closed bool
}

func newTunnel(ctx context.Context, kubeconfig, namespace string, logger *slog.Logger) (*tunnel, error) {
	t := &tunnel{kubeconfig: kubeconfig, namespace: namespace, logger: logger}
	if err := t.open(ctx); err != nil {
		return nil, err
	}

	return t, nil
}

// URL is the proxy's address through the tunnel as it stands right now.
func (t *tunnel) URL() string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return fmt.Sprintf("https://127.0.0.1:%d", t.port)
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
	port, stop, err := startPortForward(ctx, t.kubeconfig, t.namespace, func(cause error) {
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
		slog.String("error_message", cause.Error()))

	for i := 0; i < tunnelReopenAttempts; i++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		if err := t.open(ctx); err == nil {
			t.logger.Info("port-forward reopened", slog.String("url", t.URL()))

			return
		}
	}

	t.logger.Error("port-forward could not be reopened; traffic has stopped")
}

// startPortForward runs one kubectl port-forward and returns the local port it
// chose. onDeath is called if it exits on its own.
func startPortForward(ctx context.Context, kubeconfig, namespace string, onDeath func(error)) (int, func(), error) {
	// #nosec G204 -- the binary is the constant "kubectl"; the only variable
	// arguments are the operator's own --state and --namespace flags.
	cmd := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", namespace,
		"port-forward", "svc/kop-kube-oidc-proxy", ":443")
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
	client    *http.Client
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

// do issues one request against the proxy and returns its status code.
func (g *generator) do(ctx context.Context, method, path, token string, headers http.Header) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, g.tunnel.URL()+path, nil)
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

// scenario is one kind of traffic. want is the HTTP status the proxy or the
// API server must answer with; statusNone means the exchange finishes without
// one, because the connection was upgraded or the body was streamed.
type scenario struct {
	name string
	want int
	run  func(context.Context) (int, error)
}

func (g *generator) scenarios() []scenario {
	pods := fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace)

	return []scenario{
		{
			// requests_total{list,namespace,200}, the duration histogram,
			// authentication_attempts_total{oidc,accepted}, decisions{allow}.
			name: "allowed_list",
			want: http.StatusOK,
			run: func(ctx context.Context) (int, error) {
				return g.doWithValidToken(ctx, http.MethodGet, pods, nil)
			},
		},
		{
			// The same, at resource scope rather than namespace scope.
			name: "allowed_get",
			want: http.StatusOK,
			run: func(ctx context.Context) (int, error) {
				return g.doWithValidToken(ctx, http.MethodGet, pods+"/"+demoPod, nil)
			},
		},
		{
			// The proxy allows the request; the API server refuses the
			// impersonated identity. A 403 that is not a proxy denial.
			name: "forbidden_by_rbac",
			want: http.StatusForbidden,
			run: func(ctx context.Context) (int, error) {
				return g.doWithValidToken(ctx, http.MethodGet, "/api/v1/nodes", nil)
			},
		},
		{
			// Not a JWT at all: rejected by OIDC, then by the TokenReview
			// fallback. decisions{deny,unauthorized}.
			name: "invalid_token",
			want: http.StatusUnauthorized,
			run: func(ctx context.Context) (int, error) {
				return g.do(ctx, http.MethodGet, pods, "not-a-token-"+time.Now().Format(time.RFC3339Nano), nil)
			},
		},
		{
			// Correctly signed, but past its exp: the same outcome by a
			// different route through the authenticator.
			name: "expired_token",
			want: http.StatusUnauthorized,
			run: func(ctx context.Context) (int, error) {
				token, err := g.token(demoUser, []string{"demo"}, time.Now().Add(-time.Hour))
				if err != nil {
					return 0, err
				}

				return g.do(ctx, http.MethodGet, pods, token, nil)
			},
		},
		{
			// review_requests_total{sar,allow}, cache_lookups_total (a miss,
			// then hits on every later run), decisions{allow}.
			name: "impersonation_allowed",
			want: http.StatusOK,
			run: func(ctx context.Context) (int, error) {
				// Three times, back to back: the first call to each replica
				// is a cache miss and issues a real SubjectAccessReview, and
				// with two replicas a third call is guaranteed to land on one
				// that is already warm. One call on its own would only ever
				// produce misses, because the rotation comes round again long
				// after the cache entry has expired.
				headers := http.Header{"Impersonate-User": []string{impersonated}}

				return g.repeat(ctx, cacheWarmCalls, func(ctx context.Context) (int, error) {
					return g.doWithValidToken(ctx, http.MethodGet, pods, headers)
				})
			},
		},
		{
			// review_requests_total{sar,deny},
			// decisions{deny,impersonation_denied}.
			name: "impersonation_denied",
			want: http.StatusForbidden,
			run: func(ctx context.Context) (int, error) {
				return g.doWithValidToken(ctx, http.MethodGet, pods,
					http.Header{"Impersonate-User": []string{notImpersonat}})
			},
		},
		{
			// decisions{deny,too_many_impersonation_values}: refused on the
			// header count before any review is issued.
			name: "too_many_impersonation_values",
			want: http.StatusRequestHeaderFieldsTooLarge,
			run: func(ctx context.Context) (int, error) {
				headers := http.Header{"Impersonate-User": []string{impersonated}}
				for i := 0; i < 100; i++ {
					headers.Add("Impersonate-Group", fmt.Sprintf("group-%d", i))
				}

				return g.doWithValidToken(ctx, http.MethodGet, pods, headers)
			},
		},
		{
			// decisions{deny,reserved_identity}: a token claiming a group the
			// proxy will never impersonate.
			name: "reserved_identity",
			want: http.StatusForbidden,
			run: func(ctx context.Context) (int, error) {
				token, err := g.token(demoUser, []string{"system:masters"}, time.Now().Add(10*time.Minute))
				if err != nil {
					return 0, err
				}

				return g.do(ctx, http.MethodGet, pods, token, nil)
			},
		},
		{
			// authentication_attempts_total{oidc,rejected} then
			// {tokenreview,accepted}, review_requests_total{tokenreview,allow}.
			name: "passthrough_allowed",
			want: http.StatusOK,
			run: func(ctx context.Context) (int, error) {
				token, err := g.serviceAccountToken(ctx)
				if err != nil {
					return 0, err
				}

				// The same token repeatedly, so the TokenReview result is
				// cached and reused rather than reviewed again on every call.
				// A freshly minted token on each call would only ever miss.
				return g.repeat(ctx, cacheWarmCalls, func(ctx context.Context) (int, error) {
					return g.do(ctx, http.MethodGet, pods, token, nil)
				})
			},
		},
		{
			// A token the API server cannot authenticate either:
			// authentication_attempts_total{tokenreview,rejected}.
			name: "passthrough_denied",
			want: http.StatusUnauthorized,
			run: func(ctx context.Context) (int, error) {
				// Repeated with the same token, so a later lookup is served
				// from the TokenReview failure cache rather than reviewed
				// again; that is what shields the API server from a client
				// retrying a bad token in a loop.
				return g.repeat(ctx, cacheWarmCalls, func(ctx context.Context) (int, error) {
					return g.do(ctx, http.MethodGet, pods, unknownServiceAccountToken(), nil)
				})
			},
		},
		{
			// long_running_requests{watch}, released when the client goes
			// away: termination client_cancel.
			name: "watch",
			want: statusNone,
			run:  g.watch,
		},
		{
			// The hijack path: long_running_requests{connect}, termination
			// hijacked, code none.
			name: "exec",
			want: statusNone,
			run:  g.exec,
		},
		{
			// A streamed response that is long-running but not hijacked.
			name: "logs",
			want: http.StatusOK,
			run: func(ctx context.Context) (int, error) {
				return g.doWithValidToken(ctx, http.MethodGet, pods+"/"+demoPod+"/log", nil)
			},
		},
		{
			// scope none, verb get: a path with no RequestInfo resource.
			name: "non_resource",
			want: http.StatusOK,
			run: func(ctx context.Context) (int, error) {
				if _, err := g.doWithValidToken(ctx, http.MethodGet, "/version", nil); err != nil {
					return 0, err
				}

				return g.doWithValidToken(ctx, http.MethodGet, "/healthz", nil)
			},
		},
		{
			// Verbs that are not HTTP methods and not Kubernetes verbs: every
			// one must land on k8s_verb="other", scope="none", and never
			// create a new series.
			name: "hostile_methods",
			want: statusNone,
			run:  g.hostileMethods,
		},
	}
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
// projected onto k8s_verb="other" rather than creating a series each.
func (g *generator) hostileMethods(ctx context.Context) (int, error) {
	token, err := g.validToken()
	if err != nil {
		return 0, err
	}

	for i := 1; i <= 9; i++ {
		if _, err := g.do(ctx, fmt.Sprintf("M%d", i), "/apis/x/v1/y", token, nil); err != nil {
			return 0, err
		}
	}

	return statusNone, nil
}

// repeat runs the same call n times and returns the last status, so a
// scenario can warm a cache and then hit it.
func (g *generator) repeat(ctx context.Context, n int, call func(context.Context) (int, error)) (int, error) {
	var status int
	for i := 0; i < n; i++ {
		var err error
		if status, err = call(ctx); err != nil {
			return 0, err
		}
	}

	return status, nil
}

// runOnce runs every scenario once and fails if any produced an unexpected
// status. This is the test for the load generator itself.
func (g *generator) runOnce(ctx context.Context, logger *slog.Logger, scenarios []scenario) error {
	var failed []string

	for _, s := range scenarios {
		status, err := g.call(ctx, logger, s)
		switch {
		case err != nil:
			failed = append(failed, fmt.Sprintf("%s: %s", s.name, err))
		case status != s.want:
			failed = append(failed, fmt.Sprintf("%s: status %d, want %d", s.name, status, s.want))
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("%d of %d scenarios did not behave as expected:\n  %s",
			len(failed), len(scenarios), strings.Join(failed, "\n  "))
	}

	logger.Info("every scenario produced its expected status", slog.Int("scenarios", len(scenarios)))

	return nil
}

// runFor rotates through the scenarios until the duration is up, so every
// family keeps receiving traffic while the dashboards are watched.
func (g *generator) runFor(ctx context.Context, logger *slog.Logger, scenarios []scenario, duration, interval time.Duration) error {
	deadline := time.Now().Add(duration)
	for i := 0; time.Now().Before(deadline); i++ {
		s := scenarios[i%len(scenarios)]
		if _, err := g.call(ctx, logger, s); err != nil {
			// A failure mid-run is traffic too: log it and keep going, so a
			// transient API server hiccup does not end a ten-minute run.
			logger.Warn("scenario failed", slog.String("kind", s.name),
				slog.String("error_message", err.Error()))
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

// call runs one scenario and logs one record for it, so a reader can line the
// log up against the counters.
func (g *generator) call(ctx context.Context, logger *slog.Logger, s scenario) (int, error) {
	start := time.Now()
	status, err := s.run(ctx)
	elapsed := time.Since(start)

	logger.Info("call",
		slog.String("kind", s.name),
		slog.Int("status", status),
		slog.Int64("duration_ms", elapsed.Milliseconds()),
		slog.Bool("ok", err == nil && status == s.want),
	)

	return status, err
}
