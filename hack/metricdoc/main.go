// Copyright Jetstack Ltd. See LICENSE for details.

// Command metricdoc renders the metric catalogue in pkg/metrics as a markdown
// table and writes it into docs/metrics.md between the metrics:begin and
// metrics:end markers. With -check it reports a diff and exits 1 instead of
// writing, so CI fails when the file is stale.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rafpe/kube-oidc-proxy/hack/internal/docsync"
	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

var section = docsync.Section{
	Path:       "docs/metrics.md",
	Begin:      "<!-- metrics:begin -->",
	End:        "<!-- metrics:end -->",
	Title:      "Metrics",
	MakeTarget: "metricdoc",
}

func main() {
	check := flag.Bool("check", false, "report a diff and exit 1 instead of writing")
	flag.Parse()

	if err := docsync.Sync(section, renderTable(), *check); err != nil {
		fmt.Fprintf(os.Stderr, "metricdoc: %v\n", err)
		os.Exit(1)
	}
}

// renderTable renders every catalogued metric as one markdown row.
func renderTable() string {
	var b strings.Builder
	b.WriteString("| name | type | labels | stability | help |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, s := range metrics.Catalogue() {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			docsync.Escape(s.Name), s.Type, docsync.CodeList(s.Labels), s.Stability, docsync.Escape(s.Help))
	}
	return b.String()
}
