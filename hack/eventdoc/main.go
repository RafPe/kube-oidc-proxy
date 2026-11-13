// Copyright Jetstack Ltd. See LICENSE for details.

// Command eventdoc renders the event registry in pkg/logging as a markdown
// table and writes it into docs/logging.md between the events:begin and
// events:end markers. With -check it reports a diff and exits 1 instead of
// writing, so CI fails when the file is stale.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/rafpe/kube-oidc-proxy/hack/internal/docsync"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

var section = docsync.Section{
	Path:       "docs/logging.md",
	Begin:      "<!-- events:begin -->",
	End:        "<!-- events:end -->",
	Title:      "Logging",
	MakeTarget: "eventdoc",
}

func main() {
	check := flag.Bool("check", false, "report a diff and exit 1 instead of writing")
	flag.Parse()

	if err := docsync.Sync(section, renderTable(), *check); err != nil {
		fmt.Fprintf(os.Stderr, "eventdoc: %v\n", err)
		os.Exit(1)
	}
}

// renderTable renders every registered event as one markdown row, sorted by
// event_type.
func renderTable() string {
	var b strings.Builder
	b.WriteString("| `event_type` | components | level | required | summary |\n")
	b.WriteString("|---|---|---|---|---|\n")

	for _, e := range logging.AllEventTypes() {
		spec, ok := e.Spec()
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			docsync.Escape(string(e)),
			components(spec.Components),
			levels(spec),
			docsync.CodeList(spec.Required),
			docsync.Escape(spec.Summary),
		)
	}

	return b.String()
}

// levels names the level an event is emitted at, and the alternatives its
// entry allows for an event whose severity depends on the outcome.
func levels(spec logging.EventSpec) string {
	out := []string{docsync.Escape(spec.Level.String())}
	for _, l := range spec.AllowedLevels {
		out = append(out, docsync.Escape(l.String()))
	}
	return strings.Join(out, " or ")
}

// components lists the components an event may be emitted by, or "any" for an
// event the registry does not pin to one.
func components(cs []logging.Component) string {
	if len(cs) == 0 {
		return "any"
	}
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, string(c))
	}
	return docsync.CodeList(names)
}
