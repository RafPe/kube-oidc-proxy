// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

// TestRenderTableHasOneRowPerCatalogueEntry pins the table's shape: a header,
// a separator, and exactly one row per catalogued metric, in catalogue order.
func TestRenderTableHasOneRowPerCatalogueEntry(t *testing.T) {
	lines := strings.Split(strings.TrimSpace(renderTable()), "\n")
	catalogue := metrics.Catalogue()

	if got := len(lines) - 2; got != len(catalogue) {
		t.Fatalf("table has %d rows, want %d", got, len(catalogue))
	}
	for i, spec := range catalogue {
		if !strings.HasPrefix(lines[i+2], "| `"+spec.Name+"` |") {
			t.Errorf("row %d = %q, want it to start with %s", i, lines[i+2], spec.Name)
		}
	}
}
