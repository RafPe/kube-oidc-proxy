// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
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
	if !strings.Contains(msg, "metrics: listening on") || strings.Contains(msg, "missing-kubeconfig") {
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
	if seen[logging.EventProxyStartupFailed] != 0 {
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
