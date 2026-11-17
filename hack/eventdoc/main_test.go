// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// TestRenderTableHasOneRowPerRegisteredEvent pins the table's shape: a header,
// a separator, and exactly one row for every event the registry knows, each
// naming the event in a code span so the row is greppable.
func TestRenderTableHasOneRowPerRegisteredEvent(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(renderTable()), "\n")

	registered := 0
	for _, e := range logging.AllEventTypes() {
		if _, ok := e.Spec(); ok {
			registered++
		}
	}
	if got := len(lines) - 2; got != registered {
		t.Fatalf("table has %d rows, want %d (one per registered event)", got, registered)
	}
	if !strings.HasPrefix(lines[0], "| `event_type` |") || !strings.HasPrefix(lines[1], "|---|") {
		t.Fatalf("table header = %q / %q", lines[0], lines[1])
	}
	for _, row := range lines[2:] {
		// An escaped pipe is cell content, not a column boundary.
		cells := strings.Count(strings.ReplaceAll(row, `\|`, ""), "|")
		if !strings.HasPrefix(row, "| `") || cells != 6 {
			t.Errorf("malformed row %q", row)
		}
	}
}

// TestLevelsNamesEveryAllowedLevel pins that an event whose severity varies
// lists every level it may be emitted at.
func TestLevelsNamesEveryAllowedLevel(t *testing.T) {
	spec, ok := logging.EventAuthzSARFailed.Spec()
	if !ok {
		t.Fatal("authz.sar.failed is not registered")
	}
	if got := levels(spec); got != "ERROR or DEBUG" {
		t.Fatalf("levels = %q, want %q", got, "ERROR or DEBUG")
	}
}

func TestComponentsRendersAnyForUnpinnedEvents(t *testing.T) {
	if got := components(nil); got != "any" {
		t.Fatalf("components(nil) = %q, want any", got)
	}
	if got := components([]logging.Component{logging.ComponentOIDC}); got != "`oidc`" {
		t.Fatalf("components = %q", got)
	}
}
