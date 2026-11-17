// Copyright Jetstack Ltd. See LICENSE for details.
package logging_test

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"k8s.io/klog/v2"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestBridgeMapsKlogVerbosityToDebugAndTagsComponent(t *testing.T) {
	root, cap := logtest.New(t, 2)
	installKlogBridge(t, root, 2)

	klog.V(2).InfoS("throttled", "delay", "1s")
	klog.V(4).InfoS("too verbose for -v=2")
	klog.ErrorS(errors.New("boom"), "failed")
	klog.Infof("printf %s", "style")
	klog.Flush()

	recs := cap.Records()
	byMsg := map[string]logtest.Record{}
	for _, r := range recs {
		byMsg[r.String("msg")] = r
		if r.String("component") != "k8s" {
			t.Errorf("bridged record without component=k8s: %v", r)
		}
		if _, has := r["event_type"]; has {
			t.Errorf("bridged record carries event_type: %v", r)
		}
	}
	if byMsg["throttled"].String("level") != "DEBUG" || byMsg["throttled"].String("delay") != "1s" {
		t.Errorf("V(2) record: %v", byMsg["throttled"])
	}
	if _, has := byMsg["too verbose for -v=2"]; has {
		t.Error("V(4) record passed a -v=2 bridge")
	}
	if byMsg["failed"].String("level") != "ERROR" {
		t.Errorf("ErrorS record: %v", byMsg["failed"])
	}
	if byMsg["printf style"].String("level") != "INFO" {
		t.Errorf("Infof record: %v", byMsg["printf style"])
	}
}

// TestMain guards the invariant behind installKlogBridge: klog's -v is
// process-global, so no test in this package may leave it changed. Without this
// a forgotten restore surfaces later as a mysterious failure in whichever test
// happens to run next.
func TestMain(m *testing.M) {
	before := klogVerbosity()
	code := m.Run()
	if after := klogVerbosity(); after != before {
		fmt.Fprintf(os.Stderr, "klog -v leaked out of this package: %q at start, %q at end\n", before, after)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// klogVerbosity reads klog's process-global -v. klog exposes it only as a
// flag.Value, and InitFlags re-registers the existing Values rather than
// writing defaults, so a throwaway FlagSet reads the live global.
func klogVerbosity() string {
	var fs flag.FlagSet
	klog.InitFlags(&fs)
	return fs.Lookup("v").Value.String()
}

// installKlogBridge installs the bridge for one test and restores klog's -v,
// which InstallKlogBridge sets process-wide so klog's own V(n) gate agrees with
// the slog floor. The logger klog holds is never reset: the bridge is installed
// in klog once per process and only its target changes, so a goroutine a
// library leaves logging after the test cannot race a reset.
func installKlogBridge(t *testing.T, root *slog.Logger, verbosity int) {
	t.Helper()
	before := klogVerbosity()
	logging.InstallKlogBridge(root, verbosity)
	t.Cleanup(func() {
		var fs flag.FlagSet
		klog.InitFlags(&fs)
		if err := fs.Set("v", before); err != nil {
			t.Errorf("restoring klog -v to %q: %s", before, err)
		}
	})
}

func TestInstallKlogBridgeLeavesKlogVerbosityUnchanged(t *testing.T) {
	before := klogVerbosity()

	t.Run("bridge installed", func(t *testing.T) {
		root, _ := logtest.New(t, 2)
		installKlogBridge(t, root, 7)

		if got := klogVerbosity(); got != "7" {
			t.Fatalf("bridge did not carry -v to klog: got %q, want %q", got, "7")
		}
	})

	// The subtest's cleanup has run by the time t.Run returns: klog's -v is
	// process-global, so a test that installs the bridge must put it back or
	// every later test in the binary inherits it.
	if got := klogVerbosity(); got != before {
		t.Errorf("klog -v leaked out of the bridge test: got %q, want %q", got, before)
	}
}

// TestBridgeKeepsItsRulesOnDerivedLoggers covers the path Kubernetes libraries
// actually take: klog.FromContext(ctx).WithValues(...) derives a logger through
// bridgeHandler.WithAttrs, and that derived logger must still tag component=k8s
// and apply the -v gate to V(n).
func TestBridgeKeepsItsRulesOnDerivedLoggers(t *testing.T) {
	for _, verbosity := range []int{0, 1} {
		t.Run(fmt.Sprintf("v=%d", verbosity), func(t *testing.T) {
			root, cap := logtest.New(t, verbosity)
			installKlogBridge(t, root, verbosity)

			derived := klog.LoggerWithValues(klog.Background(), "k", "v")
			derived.V(1).Info("verbose")
			derived.Info("plain")
			klog.Flush()

			byMsg := map[string]logtest.Record{}
			for _, r := range cap.Records() {
				byMsg[r.String("msg")] = r
				if r.String("component") != "k8s" || r.String("k") != "v" {
					t.Errorf("derived record lost component=k8s or its value: %v", r)
				}
			}
			if _, ok := byMsg["plain"]; !ok {
				t.Errorf("INFO record from a derived logger dropped: %s", cap.Raw())
			}
			verbose, ok := byMsg["verbose"]
			switch {
			case verbosity == 0 && ok:
				t.Errorf("V(1) record from a derived logger passed a -v=0 bridge: %v", verbose)
			case verbosity == 1 && (!ok || verbose.String("level") != "DEBUG"):
				t.Errorf("V(1) record from a derived logger at -v=1 = %v, want it at DEBUG", verbose)
			}
		})
	}
}
