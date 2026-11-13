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
// the context is only cancelled by run itself, and nothing signals the test
// process.
func neverStop(parent context.Context, _ *slog.Logger) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

// restoreRunGlobals undoes what run sets process-wide once t ends: the default
// slog logger, the log package output slog.SetDefault redirects, and klog's -v,
// so later tests in the binary see none of them. klog's installed logger is not
// reset: logging.InstallKlogBridge installs it once per process and only swaps
// its target, because a Kubernetes library goroutine (the serving certificate
// reloader) can still log through it after the command has returned.
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
		if err := fs.Set("v", prevV); err != nil {
			t.Errorf("restoring klog -v to %q: %s", prevV, err)
		}
	})
}

// TestVersionPrintsAndReturnsWithoutStarting pins that --version is answered on
// the command's output and returns cleanly, so main owns the exit status: no
// flag is validated, no logger is built, and no stop trigger is installed.
func TestVersionPrintsAndReturnsWithoutStarting(t *testing.T) {
	var out bytes.Buffer
	opts := options.New()
	cmd := buildRunCommand(opts, &out, func(parent context.Context, _ *slog.Logger) (context.Context, context.CancelFunc) {
		t.Error("--version installed the stop trigger; it must return before startup")
		return context.WithCancel(parent)
	})
	opts.AddFlags(cmd)
	// An invalid configuration beside --version shows that nothing is
	// validated either.
	cmd.SetArgs([]string{"--version", "--oidc-issuer-url=https://issuer.example.com"})
	var cmdOut, cmdErr bytes.Buffer
	cmd.SetOut(&cmdOut)
	cmd.SetErr(&cmdErr)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() = %v, want nil", err)
	}
	if !strings.HasPrefix(cmdOut.String(), options.AppName+" version: ") || !strings.Contains(cmdOut.String(), "GitVersion:") {
		t.Errorf("command output = %q, want the version information", cmdOut.String())
	}
	if out.Len() != 0 || cmdErr.Len() != 0 {
		t.Errorf("--version wrote outside the command output: log=%q stderr=%q", out.String(), cmdErr.String())
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

	// No port is reserved and then released for the command to bind, which
	// another process could take in between. The secure listener is bound
	// here and handed over through SecureServing.Listener, which ApplyTo
	// serves on as given (--secure-port=0 would turn secure serving off
	// instead). The readiness listener binds port 0 and the test reads the
	// port back from readiness.server.started. Only the metrics port is
	// reserved and released, because --metrics-bind-address refuses port 0:
	// a scrape target must know its port in advance.
	secureListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The command owns the listener once started; this only frees it when
	// the command fails before serving.
	t.Cleanup(func() { _ = secureListener.Close() })
	securePort := secureListener.Addr().(*net.TCPAddr).Port
	metricsPort := freePort(t)

	var out syncBuffer
	stopCtx, stop := context.WithCancel(context.Background())
	defer stop()
	opts := options.New()
	opts.SecureServing.Listener = secureListener
	cmd := buildRunCommand(opts, &out, func(parent context.Context, _ *slog.Logger) (context.Context, context.CancelFunc) {
		// The test's stop trigger stands in for the first signal.
		ctx, cancel := context.WithCancel(parent)
		context.AfterFunc(stopCtx, cancel)
		return ctx, cancel
	})
	opts.AddFlags(cmd)
	cmd.SetArgs([]string{
		"--oidc-issuer-url=" + issuer.URL,
		"--oidc-client-id=kube-oidc-proxy",
		"--oidc-ca-file=" + writeCA(t, dir, "issuer-ca.pem", issuer),
		"--server=" + apiServer.URL,
		"--certificate-authority=" + writeCA(t, dir, "api-ca.pem", apiServer),
		"--bind-address=127.0.0.1",
		"--tls-cert-file=" + certFile,
		"--tls-private-key-file=" + keyFile,
		"--readiness-probe-port=0",
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

	deadline := time.Now().Add(30 * time.Second)
	var readyURL string
	for {
		if readyURL == "" {
			if port, ok := startedPort(t, out.String(), logging.EventReadinessServerStarted); ok {
				readyURL = "http://127.0.0.1:" + port + "/ready"
			}
		}
		if readyURL != "" {
			if code, err := get(readyURL); err == nil && code == http.StatusOK {
				break
			}
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

	stop()
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

// startedPort returns the port in the address of the first event record on
// stream, once the listener reporting it has bound.
func startedPort(t *testing.T, stream string, event logging.EventType) (string, bool) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["event_type"] != string(event) {
			continue
		}
		address, _ := rec["address"].(string)
		_, port, err := net.SplitHostPort(address)
		if err != nil {
			t.Fatalf("%s address = %q: %v", event, address, err)
		}
		return port, true
	}
	return "", false
}

// freePort returns a loopback port that was free a moment ago. The listener
// is released before the command binds it, a race the one caller accepts for
// the metrics port only.
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
