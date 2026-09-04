// Copyright Jetstack Ltd. See LICENSE for details.
package logging_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestLevelForVerbosity(t *testing.T) {
	if logging.LevelFor(0) != slog.LevelInfo || logging.LevelFor(1) != slog.LevelDebug || logging.LevelFor(10) != slog.LevelDebug {
		t.Fatal("LevelFor: 0 must be INFO, >=1 must be DEBUG")
	}
}

func TestRootAddsSchemaVersionAndComponent(t *testing.T) {
	root, cap := logtest.New(t, 0)
	l := logging.ForComponent(root, logging.ComponentStartup)
	logging.Emit(context.Background(), l, logging.EventProxyServerStarted, slog.String("address", ":6443"))

	rec := cap.Only(t, logging.EventProxyServerStarted)
	if v, _ := rec.Int("schema_version"); v != 1 {
		t.Errorf("schema_version = %v", rec["schema_version"])
	}
	if rec.String("component") != "startup" {
		t.Errorf("component = %q", rec.String("component"))
	}
	if rec.String("level") != "INFO" || rec.String("msg") == "" {
		t.Errorf("level/msg not taken from registry: %v", rec)
	}
}

func TestDebugHiddenAtVerbosityZero(t *testing.T) {
	root, cap := logtest.New(t, 0)
	logging.Emit(context.Background(), root, logging.EventCacheSARLookup,
		slog.String("request_id", "x"), slog.String("cache_result", "hit"))
	if len(cap.Records()) != 0 {
		t.Fatalf("DEBUG record emitted at -v=0: %v", cap.Records())
	}
	root2, cap2 := logtest.New(t, 2)
	logging.Emit(context.Background(), root2, logging.EventCacheSARLookup,
		slog.String("request_id", "x"), slog.String("cache_result", "hit"))
	if len(cap2.Records()) != 1 {
		t.Fatalf("DEBUG record missing at -v=2")
	}
}

func TestEmitPanicsOnMissingRequiredFieldUnderLogcheck(t *testing.T) {
	root, _ := logtest.New(t, 0)
	defer func() {
		if recover() == nil {
			t.Fatal("Emit did not panic on a missing required field with -tags logcheck")
		}
	}()
	logging.Emit(context.Background(), root, logging.EventProxyServerStarted) // address missing
}

func TestFromContextReturnsDiscardWhenAbsent(t *testing.T) {
	l := logging.FromContext(context.Background())
	if l == nil {
		t.Fatal("nil logger")
	}
	l.Info("must not panic")
}

func TestTextFormatIsValid(t *testing.T) {
	if err := (logging.Options{Format: "yaml"}).Validate(); err == nil {
		t.Fatal("yaml accepted")
	}
	if err := (logging.Options{Format: logging.FormatText}).Validate(); err != nil {
		t.Fatal(err)
	}
}
