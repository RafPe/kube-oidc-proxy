// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes/fake"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/authn"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy"
	"github.com/rafpe/kube-oidc-proxy/pkg/proxy/audit"
)

// neverStop is the stop trigger for a run that is expected to fail at startup:
// a nil channel never fires, and nothing signals the test process.
func neverStop(*slog.Logger) <-chan struct{} { return nil }

// restoreRunGlobals undoes what run sets process-wide once t ends: the default
// slog logger and the log package output slog.SetDefault redirects, and klog's
// installed logger and -v, which the klog bridge sets, so later tests in the
// binary see none of them.
func restoreRunGlobals(t *testing.T) {
	t.Helper()
	prevDefault := slog.Default()
	prevLogOutput, prevLogFlags := log.Writer(), log.Flags()
	var fs flag.FlagSet
	klog.InitFlags(&fs)
	prevV := fs.Lookup("v").Value.String()
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		log.SetOutput(prevLogOutput)
		log.SetFlags(prevLogFlags)
		klog.ClearLogger()
		if err := fs.Set("v", prevV); err != nil {
			t.Errorf("restoring klog -v to %q: %s", prevV, err)
		}
	})
}

func TestCheckReservedIdentityPrefixes(t *testing.T) {
	tests := map[string]struct {
		usernamePrefix string
		groupsPrefix   string
		configFile     string
		wantErr        bool
	}{
		"no prefixes": {},
		"ordinary prefixes": {
			usernamePrefix: "oidc:",
			groupsPrefix:   "oidc:",
		},
		"reserved username prefix": {
			usernamePrefix: "system:",
			wantErr:        true,
		},
		"reserved groups prefix": {
			groupsPrefix: "system:serviceaccount:",
			wantErr:      true,
		},
		// --oidc-* prefixes are ignored entirely when an authentication
		// configuration file is in use, so they must not fail startup.
		"reserved prefix ignored in multi-issuer mode": {
			usernamePrefix: "system:",
			configFile:     "/etc/kube-oidc-proxy/authentication.yaml",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			opts := &options.Options{
				OIDCAuthentication: &options.OIDCAuthenticationOptions{
					UsernamePrefix: test.usernamePrefix,
					GroupsPrefix:   test.groupsPrefix,
				},
				AuthenticationConfig: &options.AuthenticationConfigOptions{ConfigFile: test.configFile},
				App:                  &options.KubeOIDCProxyOptions{},
			}

			err := checkReservedIdentityPrefixes(opts)

			if test.wantErr && err == nil {
				t.Error("checkReservedIdentityPrefixes() = nil, want an error")
			}
			if !test.wantErr && err != nil {
				t.Errorf("checkReservedIdentityPrefixes() = %v, want nil", err)
			}
		})
	}
}

// TestLogConfigLoaded pins the startup record that fixes what this pod is
// configured to do. It is the record an operator diffs between two pods, so
// every field it promises must be present and carry the value it was given.
func TestLogConfigLoaded(t *testing.T) {
	root, cap := logtest.New(t, 0)

	logConfigLoaded(logging.ForComponent(root, logging.ComponentStartup), configSummary{
		version:       "v1.5.0",
		configHash:    "0123456789abcdef",
		issuerCount:   2,
		readinessMode: "all",
	})

	rec := cap.Only(t, logging.EventProxyConfigLoaded)
	if rec.String("version") != "v1.5.0" {
		t.Errorf("version = %q", rec.String("version"))
	}
	if rec.String("config_hash") != "0123456789abcdef" {
		t.Errorf("config_hash = %q", rec.String("config_hash"))
	}
	if got, ok := rec.Int("issuer_count"); !ok || got != 2 {
		t.Errorf("issuer_count = %v", rec["issuer_count"])
	}
	if rec.String("readiness_mode") != "all" {
		t.Errorf("readiness_mode = %q", rec.String("readiness_mode"))
	}
	if rec.String("component") != string(logging.ComponentStartup) {
		t.Errorf("component = %q, want startup", rec.String("component"))
	}
}

// TestStartupFailureAfterLoggerIsReportedAsARecord pins that an error raised
// once the root logger exists is emitted as proxy.startup.failed on the
// configured stream and returned as ErrReported, so main exits non-zero without
// appending a second, unstructured line to the container log.
func TestStartupFailureAfterLoggerIsReportedAsARecord(t *testing.T) {
	restoreRunGlobals(t)
	var out bytes.Buffer
	opts := options.New()
	cmd := buildRunCommand(opts, &out, neverStop)
	opts.AddFlags(cmd)
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=kube-oidc-proxy",
		"--kubeconfig=" + filepath.Join(t.TempDir(), "missing-kubeconfig"),
	})
	var cmdOut, cmdErr bytes.Buffer
	cmd.SetOut(&cmdOut)
	cmd.SetErr(&cmdErr)

	err := cmd.Execute()
	if !errors.Is(err, ErrReported) {
		t.Fatalf("Execute() error = %v, want ErrReported", err)
	}
	// cobra must not print the error or the usage text: the record is the
	// only report, and main prints nothing for ErrReported.
	if cmdOut.Len() != 0 || cmdErr.Len() != 0 {
		t.Fatalf("command wrote outside the log stream: stdout=%q stderr=%q", cmdOut.String(), cmdErr.String())
	}

	// Every line of the whole stream is one JSON record, and the failure is
	// reported exactly once.
	var failures []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("non-JSON line on the log stream: %q", line)
		}
		if rec["event_type"] == string(logging.EventProxyStartupFailed) {
			failures = append(failures, rec)
		}
	}
	if len(failures) != 1 {
		t.Fatalf("want exactly one proxy.startup.failed record, got %d:\n%s", len(failures), out.String())
	}
	rec := failures[0]
	if rec["level"] != "ERROR" || rec["component"] != string(logging.ComponentStartup) {
		t.Errorf("level/component = %v/%v, want ERROR/startup", rec["level"], rec["component"])
	}
	msg, _ := rec["error_message"].(string)
	if !strings.Contains(msg, "missing-kubeconfig") {
		t.Errorf("error_message = %q, want the underlying cause", msg)
	}
}

// TestMetricsBindFailureIsReportedAtStartup pins two things: the metrics
// listener binds before anything that needs a cluster, and a port already in
// use is a startup failure on the log stream rather than a crash later.
func TestMetricsBindFailureIsReportedAtStartup(t *testing.T) {
	restoreRunGlobals(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var out bytes.Buffer
	opts := options.New()
	cmd := buildRunCommand(opts, &out, neverStop)
	opts.AddFlags(cmd)
	cmd.SetArgs([]string{
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=kube-oidc-proxy",
		"--metrics-bind-address=" + ln.Addr().String(),
		"--kubeconfig=" + filepath.Join(t.TempDir(), "missing-kubeconfig"),
	})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	if err := cmd.Execute(); !errors.Is(err, ErrReported) {
		t.Fatalf("Execute() error = %v, want ErrReported", err)
	}

	var failure map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("non-JSON line on the log stream: %q", line)
		}
		if rec["event_type"] == string(logging.EventProxyStartupFailed) {
			failure = rec
		}
	}
	if failure == nil {
		t.Fatalf("no proxy.startup.failed record:\n%s", out.String())
	}
	msg, _ := failure["error_message"].(string)
	if !strings.Contains(msg, "metrics listener") || strings.Contains(msg, "missing-kubeconfig") {
		t.Fatalf("error_message = %q, want the metrics bind failure, reported before the kubeconfig is read", msg)
	}
}

// TestRunServesUntilStoppedThenShutsDownCleanly drives the whole command in
// process: startup against a fake API server and a fake OIDC issuer, readiness
// flipping once the proxy serves and the issuer's keys are loaded, and a clean
// exit with the shutdown records once the stop trigger fires.
func TestRunServesUntilStoppedThenShutsDownCleanly(t *testing.T) {
	restoreRunGlobals(t)
	dir := t.TempDir()

	apiServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(apiServer.Close)
	issuer := newFakeIssuer(t)

	certFile, keyFile := writeServingCert(t, dir)
	securePort, readinessPort, metricsPort := freePort(t), freePort(t), freePort(t)

	var out syncBuffer
	stop := make(chan struct{})
	opts := options.New()
	cmd := buildRunCommand(opts, &out, func(*slog.Logger) <-chan struct{} { return stop })
	opts.AddFlags(cmd)
	cmd.SetArgs([]string{
		"--oidc-issuer-url=" + issuer.URL,
		"--oidc-client-id=kube-oidc-proxy",
		"--oidc-ca-file=" + writeCA(t, dir, "issuer-ca.pem", issuer),
		"--server=" + apiServer.URL,
		"--certificate-authority=" + writeCA(t, dir, "api-ca.pem", apiServer),
		"--bind-address=127.0.0.1",
		"--secure-port=" + strconv.Itoa(securePort),
		"--tls-cert-file=" + certFile,
		"--tls-private-key-file=" + keyFile,
		"--readiness-probe-port=" + strconv.Itoa(readinessPort),
		"--metrics-bind-address=127.0.0.1:" + strconv.Itoa(metricsPort),
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	done := make(chan error, 1)
	go func() { done <- cmd.Execute() }()

	// Keep-alives off so no idle connection holds a listener's drain open.
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			// The proxy's serving certificate is self-signed by the test.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only self-signed serving certificate
		},
	}
	get := func(url string) (int, error) {
		resp, err := client.Get(url)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode, nil
	}

	readyURL := fmt.Sprintf("http://127.0.0.1:%d/ready", readinessPort)
	deadline := time.Now().Add(30 * time.Second)
	for {
		if code, err := get(readyURL); err == nil && code == http.StatusOK {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("command exited before readiness: %v\n%s", err, out.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("readiness never reported ready:\n%s", out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}

	// The proxy itself is serving: a request without credentials is refused
	// by the proxy rather than forwarded.
	if code, err := get(fmt.Sprintf("https://127.0.0.1:%d/api", securePort)); err != nil || code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated request = %d, %v; want 401", code, err)
	}

	close(stop)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Execute() = %v, want a clean exit:\n%s", err, out.String())
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("command did not exit after the stop trigger:\n%s", out.String())
	}

	seen := map[logging.EventType]int{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("non-JSON line on the log stream: %q", line)
		}
		event, _ := rec["event_type"].(string)
		seen[logging.EventType(event)]++
	}
	for _, want := range []logging.EventType{
		logging.EventProxyServerStarted,
		logging.EventReadinessProxyReady,
		logging.EventProxyServerStopped,
		logging.EventProxyHookCompleted,
		logging.EventProxyShutdownCompleted,
	} {
		if seen[want] != 1 {
			t.Errorf("%s records = %d, want 1", want, seen[want])
		}
	}
	if seen[logging.EventProxyStartupFailed] != 0 || seen[logging.EventProxyHookFailed] != 0 {
		t.Errorf("unexpected failure records:\n%s", out.String())
	}
}

// syncBuffer is a bytes.Buffer safe to write from the command's goroutines
// while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freePort returns a loopback port that was free a moment ago. The listener
// is released before the command binds it, which is a race the test accepts.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// writeCA writes srv's certificate to dir/name as a PEM bundle, which is how
// the command is told to trust it.
func writeCA(t *testing.T, dir, name string, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeServingCert writes a self-signed loopback certificate and key for the
// proxy's secure listener.
func writeServingCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	certPEM, keyPEM, err := certutil.GenerateSelfSignedCertKey("127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "serving.crt"), filepath.Join(dir, "serving.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// newFakeIssuer serves the two documents an OIDC authenticator fetches before
// it can verify tokens: the discovery document naming the server as its own
// issuer, and a JWKS holding one RSA key. Once both are fetched the issuer
// counts as initialized, which is what readiness waits for.
func newFakeIssuer(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks, err := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": "test",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}})
	if err != nil {
		t.Fatal(err)
	}

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   srv.URL,
			"jwks_uri": srv.URL + "/keys",
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestDrainStopsTheMetricsListenerAfterTheHooks pins the shutdown order. The
// proxy's pre-shutdown step reports its own failures through the recorder -- the
// audit backend increments the operation="shutdown" counter from inside one --
// so stopping the metrics listener before they run makes those series
// unscrapeable for the whole life of the process.
func TestDrainStopsTheMetricsListenerAfterTheHooks(t *testing.T) {
	var order []string
	note := func(step string) func() error {
		return func() error { order = append(order, step); return nil }
	}

	err := drain(note("wait probe"), note("flush audit"), note("stop metrics"))
	if err != nil {
		t.Fatalf("drain: %v", err)
	}

	want := []string{"wait probe", "flush audit", "stop metrics"}
	if !slices.Equal(order, want) {
		t.Fatalf("drain order = %v, want %v", order, want)
	}
}

// TestDrainJoinsEveryFailure pins that no step is skipped because an earlier
// one failed and that every failure reaches the exit status.
func TestDrainJoinsEveryFailure(t *testing.T) {
	probeErr := errors.New("probe drain overran")
	hooksErr := errors.New("audit flush failed")
	metricsErr := errors.New("metrics drain overran")

	ran := 0
	err := drain(
		func() error { ran++; return probeErr },
		func() error { ran++; return hooksErr },
		func() error { ran++; return metricsErr },
	)
	if ran != 3 {
		t.Fatalf("ran %d steps, want 3", ran)
	}
	for _, want := range []error{probeErr, hooksErr, metricsErr} {
		if !errors.Is(err, want) {
			t.Fatalf("drain error = %v, want it to carry %v", err, want)
		}
	}
}

// TestDrainKeepsTheMetricsEndpointUpForTheHooks is the property the order
// exists for: a scrape that lands while the hooks are running still reaches
// the listener and sees what a hook just recorded.
func TestDrainKeepsTheMetricsEndpointUpForTheHooks(t *testing.T) {
	rec, err := metrics.New(metrics.BuildInfo{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	srv := metrics.NewServer(metrics.ServerConfig{Addr: "127.0.0.1:0", Recorder: rec}, slog.New(slog.DiscardHandler))
	ctx, cancelMetrics := context.WithCancel(context.Background())
	defer cancelMetrics()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addr := srv.Addr()

	var body string
	hooks := func() error {
		// What the audit backend's pre-shutdown hook does.
		rec.AuditBackendFailure(metrics.AuditShutdown)

		resp, err := http.Get("http://" + addr + "/metrics")
		if err != nil {
			return fmt.Errorf("scraping during the drain window: %w", err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		body = string(raw)
		return nil
	}

	if err := drain(func() error { return nil }, hooks,
		func() error { cancelMetrics(); return srv.Wait() }); err != nil {
		t.Fatalf("drain: %v", err)
	}

	if !strings.Contains(body, `kube_oidc_proxy_audit_backend_failures_total{operation="shutdown"} 1`) {
		t.Fatalf("the shutdown series was not scrapeable during the drain window:\n%s", body)
	}
}

// TestDrainWithoutMetricsListener pins the disabled-metrics path: there is no
// listener to stop, and the other steps still run.
func TestDrainWithoutMetricsListener(t *testing.T) {
	ran := 0
	step := func() error { ran++; return nil }
	if err := drain(step, step, noStep); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if ran != 2 {
		t.Fatalf("ran %d steps, want 2", ran)
	}
}

// parsedOptions registers every flag the command does and parses args, so a
// mapping test reads the options exactly as RunE would.
func parsedOptions(t *testing.T, args ...string) *options.Options {
	t.Helper()
	opts := options.New()
	cmd := &cobra.Command{Use: options.AppName}
	opts.AddFlags(cmd)
	if err := cmd.Flags().Parse(args); err != nil {
		t.Fatalf("parsing %v: %v", args, err)
	}
	return opts
}

// TestAuthenticatorConfigMapsEveryOIDCFlag pins the flag-to-config mapping
// for the authenticator: a flag that parses but never reaches authn.Config is
// silently ignored at runtime, and only the kind e2e suite would notice.
func TestAuthenticatorConfigMapsEveryOIDCFlag(t *testing.T) {
	opts := parsedOptions(t,
		"--oidc-issuer-url=https://issuer.example.com",
		"--oidc-client-id=client",
		"--oidc-ca-file=/ca.pem",
		"--oidc-username-claim=email",
		"--oidc-username-prefix=oidc:",
		"--oidc-groups-claim=groups",
		"--oidc-groups-prefix=oidc:",
		"--oidc-signing-algs=RS256,ES256",
		"--oidc-required-claim=hd=example.com",
		"--oidc-tls-client-cert-file=/client.crt",
		"--oidc-tls-client-key-file=/client.key",
		"--authentication-config=/authn.yaml",
	)

	want := authn.Config{
		ConfigFile: "/authn.yaml",
		Issuer: authn.IssuerConfig{
			URL:            "https://issuer.example.com",
			ClientID:       "client",
			CAFile:         "/ca.pem",
			UsernameClaim:  "email",
			UsernamePrefix: "oidc:",
			GroupsClaim:    "groups",
			GroupsPrefix:   "oidc:",
			SigningAlgs:    []string{"RS256", "ES256"},
			RequiredClaims: map[string]string{"hd": "example.com"},
		},
		TLSClientCertFile: "/client.crt",
		TLSClientKeyFile:  "/client.key",
	}
	if got := authenticatorConfig(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("authenticatorConfig:\n got %+v\nwant %+v", got, want)
	}
}

// TestProxyConfigMapsEveryProxyFlag pins the flag-to-config mapping for the
// proxy itself.
func TestProxyConfigMapsEveryProxyFlag(t *testing.T) {
	opts := parsedOptions(t,
		"--token-passthrough",
		"--disable-impersonation",
		"--flush-interval=2s",
		"--bind-address=10.0.0.1",
		"--extra-user-headers=team=a,team=b",
		"--extra-user-header-client-ip",
		"--trusted-proxies=10.0.0.0/8",
		"--allow-reserved-groups=system:masters",
	)

	want := &proxy.Config{
		TokenPassthrough:                true,
		DisableImpersonation:            true,
		FlushInterval:                   2 * time.Second,
		ExtraUserHeaders:                map[string][]string{"team": {"a", "b"}},
		ExtraUserHeadersClientIPEnabled: true,
		TrustedProxies:                  []string{"10.0.0.0/8"},
		AllowedReservedGroups:           []string{"system:masters"},
	}
	if got := proxyConfig(opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("proxyConfig:\n got %+v\nwant %+v", got, want)
	}
}

// TestBuildTokenReviewerOnlyWithPassthrough pins that the reviewer exists
// exactly when passthrough is enabled: a nil reviewer is how the proxy knows
// to skip the TokenReview fallback.
func TestBuildTokenReviewerOnlyWithPassthrough(t *testing.T) {
	client := fake.NewSimpleClientset()
	discard := slog.New(slog.DiscardHandler)

	if r := buildTokenReviewer(parsedOptions(t), client, nil, discard); r != nil {
		t.Fatalf("reviewer built with passthrough disabled: %T", r)
	}
	if r := buildTokenReviewer(parsedOptions(t, "--token-passthrough"), client, nil, discard); r == nil {
		t.Fatal("no reviewer built with passthrough enabled")
	}
}

// TestIssuerProbesCoverEveryIssuer pins one readiness entry per issuer, in
// configuration order.
func TestIssuerProbesCoverEveryIssuer(t *testing.T) {
	urls := []string{"https://a.example.com", "https://b.example.com"}
	probes, err := issuerProbes(urls)
	if err != nil {
		t.Fatalf("issuerProbes: %v", err)
	}
	if len(probes) != len(urls) {
		t.Fatalf("got %d probes, want %d", len(probes), len(urls))
	}
	for i, p := range probes {
		if p.IssuerURL != urls[i] || p.FakeJWT == "" {
			t.Fatalf("probe %d = %+v, want issuer %q with a token", i, p, urls[i])
		}
	}
}

// TestConfigHash pins the three properties the startup record relies on: the
// digest is stable, it changes with any non-secret value, and it never
// depends on a secret, so two pods differing only in a credential compare
// equal and the digest cannot be used to test a guessed credential.
func TestConfigHash(t *testing.T) {
	hash := func(args ...string) string {
		t.Helper()
		fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
		fs.String("issuer", "", "")
		fs.String("token", "", "")
		fs.String("password", "", "")
		if err := fs.Parse(args); err != nil {
			t.Fatal(err)
		}
		return configHash(fs)
	}

	base := hash("--issuer=https://a")
	if len(base) != configHashLength {
		t.Fatalf("hash %q has length %d, want %d", base, len(base), configHashLength)
	}
	if again := hash("--issuer=https://a"); again != base {
		t.Fatalf("hash not stable: %q then %q", base, again)
	}
	if other := hash("--issuer=https://b"); other == base {
		t.Fatal("hash unchanged by a different issuer")
	}
	if secret := hash("--issuer=https://a", "--token=t0k3n", "--password=pw"); secret != base {
		t.Fatalf("hash depends on a secret flag: %q vs %q", secret, base)
	}
}

// TestFlushAuditStepReportsAHookRecord pins the pre-shutdown record: one
// proxy.hook.completed naming the audit backend step, under the shutdown
// component, with its duration.
func TestFlushAuditStepReportsAHookRecord(t *testing.T) {
	root, logs := logtest.New(t, 0)
	defer logtest.AssertRegistered(t, logs)

	auditor, err := audit.New(audit.Config{ExternalAddress: "0.0.0.0:1234"},
		logging.ForComponent(root, logging.ComponentAudit))
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	if err := flushAuditStep(auditor, root)(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	rec := logs.Only(t, logging.EventProxyHookCompleted)
	if got := rec.String("hook"); got != auditHook {
		t.Errorf("hook = %q, want %q", got, auditHook)
	}
	if got := rec.String("component"); got != string(logging.ComponentShutdown) {
		t.Errorf("component = %q, want shutdown", got)
	}
	if _, ok := rec.Int("duration_ms"); !ok {
		t.Error("duration_ms missing")
	}
}
