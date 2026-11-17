// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// TestBridgeHandlerWithGroupKeepsItsRules pins that a grouped bridge handler
// is still a bridge: the V(n) gate survives WithGroup, and the component tag
// stays a top-level field rather than moving into the group. klog does not
// reach WithGroup on its own, so the handler is driven directly.
func TestBridgeHandlerWithGroupKeepsItsRules(t *testing.T) {
	var buf bytes.Buffer
	inner := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}).
		WithAttrs([]slog.Attr{slog.String("component", string(ComponentK8s))})
	h := bridgeHandler{inner: inner, verbosity: 1}.WithGroup("g")

	if _, ok := h.(bridgeHandler); !ok {
		t.Fatalf("WithGroup returned %T, want a bridgeHandler", h)
	}
	if h.Enabled(context.Background(), slog.Level(-2)) {
		t.Error("a grouped bridge at -v=1 enabled V(2)")
	}
	if !h.Enabled(context.Background(), slog.Level(-1)) {
		t.Error("a grouped bridge at -v=1 refused V(1)")
	}

	if err := h.Handle(context.Background(), slog.NewRecord(time.Time{}, slog.Level(-1), "grouped", 0)); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("decoding %q: %s", buf.String(), err)
	}
	if rec["level"] != "DEBUG" {
		t.Errorf("level = %v, want DEBUG", rec["level"])
	}
	if rec["component"] != string(ComponentK8s) {
		t.Errorf("component is not a top-level field of the grouped record: %s", buf.String())
	}
}
