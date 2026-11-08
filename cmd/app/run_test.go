// Copyright Jetstack Ltd. See LICENSE for details.
package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/cmd/app/options"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

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
	var out bytes.Buffer
	opts := options.New()
	cmd := buildRunCommand(opts, &out)
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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var out bytes.Buffer
	opts := options.New()
	cmd := buildRunCommand(opts, &out)
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

// TestDrainStopsTheMetricsListenerAfterTheHooks pins the shutdown order. The
// pre-shutdown hooks report their own failures through the recorder -- the
// audit backend increments the operation="shutdown" counter from inside one --
// so stopping the metrics listener before they run makes those series
// unscrapeable for the whole life of the process.
func TestDrainStopsTheMetricsListenerAfterTheHooks(t *testing.T) {
	var order []string
	note := func(step string) func() error {
		return func() error { order = append(order, step); return nil }
	}

	err := drain(
		func() { order = append(order, "stop probe") },
		note("wait probe"),
		note("hooks"),
		note("stop metrics"),
		note("wait metrics"),
	)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}

	want := []string{"stop probe", "wait probe", "hooks", "stop metrics", "wait metrics"}
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
		func() {},
		func() error { ran++; return probeErr },
		func() error { ran++; return hooksErr },
		func() error { ran++; return nil },
		func() error { ran++; return metricsErr },
	)
	if ran != 4 {
		t.Fatalf("ran %d steps, want 4", ran)
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
	srv := metrics.NewServer("127.0.0.1:0", rec, slog.New(slog.DiscardHandler))
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

	if err := drain(func() {}, func() error { return nil }, hooks,
		func() error { cancelMetrics(); return nil }, srv.Wait); err != nil {
		t.Fatalf("drain: %v", err)
	}

	if !strings.Contains(body, `kube_oidc_proxy_audit_backend_failures_total{operation="shutdown"} 1`) {
		t.Fatalf("the shutdown series was not scrapeable during the drain window:\n%s", body)
	}
}
