// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

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

// TestLateStartupFailureStopsWhatStarted pins a startup failure after the
// readiness listener and the audit backend have started: the proxy's own
// Start fails. The failure is one proxy.startup.failed record and an
// ErrReported return, and the listeners already serving -- readiness and
// metrics -- are released by the time the command returns, rather than left
// to a context cancelled after it.
func TestLateStartupFailureStopsWhatStarted(t *testing.T) {
	restoreRunGlobals(t)
	dir := t.TempDir()

	issuer := newFakeIssuer(t)
	certFile, keyFile := writeServingCert(t, dir)

	// The secure listener is handed over as in
	// TestRunServesUntilStoppedThenShutsDownCleanly. The proxy never serves
	// it, so the test closes it.
	secureListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = secureListener.Close() })
	metricsPort := freePort(t)

	// The audit backend is only built with a policy.
	policyFile := filepath.Join(dir, "audit-policy.yaml")
	policy := "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: Metadata\n"
	if err := os.WriteFile(policyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	var out syncBuffer
	opts := options.New()
	opts.SecureServing.Listener = secureListener
	cmd := buildRunCommand(opts, &out, neverStop)
	opts.AddFlags(cmd)
	cmd.SetArgs([]string{
		"--oidc-issuer-url=" + issuer.URL,
		"--oidc-client-id=kube-oidc-proxy",
		"--oidc-ca-file=" + writeCA(t, dir, "issuer-ca.pem", issuer),
		// A server without a scheme is one client-go accepts, defaulting it
		// to https, but the proxy's own parse of the upstream URL refuses:
		// the failure surfaces only in the proxy's Start, after the readiness
		// listener and the audit backend are up. Nothing dials it.
		"--server=127.0.0.1:6443",
		"--bind-address=127.0.0.1",
		"--tls-cert-file=" + certFile,
		"--tls-private-key-file=" + keyFile,
		"--readiness-probe-port=0",
		"--metrics-bind-address=127.0.0.1:" + strconv.Itoa(metricsPort),
		"--audit-policy-file=" + policyFile,
		"--audit-log-path=" + filepath.Join(dir, "audit.log"),
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)

	if err := cmd.Execute(); !errors.Is(err, ErrReported) {
		t.Fatalf("Execute() error = %v, want ErrReported", err)
	}

	seen := map[logging.EventType]int{}
	var failure map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("non-JSON line on the log stream: %q", line)
		}
		event, _ := rec["event_type"].(string)
		seen[logging.EventType(event)]++
		if event == string(logging.EventProxyStartupFailed) {
			failure = rec
		}
	}
	for _, want := range []logging.EventType{
		logging.EventReadinessServerStarted,
		logging.EventAuditBackendStarted,
		logging.EventProxyStartupFailed,
	} {
		if seen[want] != 1 {
			t.Errorf("%s records = %d, want 1:\n%s", want, seen[want], out.String())
		}
	}
	if seen[logging.EventProxyServerStarted] != 0 {
		t.Errorf("proxy.server.started reported for a proxy that never served:\n%s", out.String())
	}
	if msg, _ := failure["error_message"].(string); !strings.Contains(msg, "proxy: parsing API server URL") {
		t.Errorf("error_message = %q, want the proxy's Start failure", msg)
	}

	// Both listeners were serving before the failure; neither may still be.
	readinessPort, ok := startedPort(t, out.String(), logging.EventReadinessServerStarted)
	if !ok {
		t.Fatalf("no readiness listener address on the stream:\n%s", out.String())
	}
	for name, addr := range map[string]string{
		"readiness": net.JoinHostPort("0.0.0.0", readinessPort),
		"metrics":   net.JoinHostPort("127.0.0.1", strconv.Itoa(metricsPort)),
	} {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("%s listener %s is still bound after the command returned: %v", name, addr, err)
			continue
		}
		_ = ln.Close()
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
