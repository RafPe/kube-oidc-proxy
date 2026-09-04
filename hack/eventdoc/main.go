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

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

const (
	docPath     = "docs/logging.md"
	beginMarker = "<!-- events:begin -->"
	endMarker   = "<!-- events:end -->"

	skeleton = `# Logging

` + beginMarker + `
` + endMarker + `
`
)

func main() {
	check := flag.Bool("check", false, "report a diff and exit 1 instead of writing")
	flag.Parse()

	if err := run(*check); err != nil {
		fmt.Fprintf(os.Stderr, "eventdoc: %v\n", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	current, err := os.ReadFile(docPath)
	switch {
	case os.IsNotExist(err):
		current = []byte(skeleton)
	case err != nil:
		return err
	}

	want, err := replaceSection(string(current), renderTable())
	if err != nil {
		return err
	}

	if want == string(current) {
		return nil
	}
	if check {
		return fmt.Errorf("%s is out of date: run `make eventdoc` and commit the result", docPath)
	}
	// docPath is a compile-time constant relative to the repository root, so
	// gosec's G703 taint warning here has no reachable attacker input.
	return os.WriteFile(docPath, []byte(want), 0600) //nolint:gosec // constant path, no user input
}

// replaceSection swaps the text between the two markers for table, keeping
// everything outside them untouched.
func replaceSection(doc, table string) (string, error) {
	begin := strings.Index(doc, beginMarker)
	if begin < 0 {
		return "", fmt.Errorf("%s does not contain %s", docPath, beginMarker)
	}
	end := strings.Index(doc, endMarker)
	if end < 0 {
		return "", fmt.Errorf("%s does not contain %s", docPath, endMarker)
	}
	if end < begin {
		return "", fmt.Errorf("%s has %s before %s", docPath, endMarker, beginMarker)
	}
	return doc[:begin+len(beginMarker)] + "\n" + table + doc[end:], nil
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
			escape(string(e)),
			components(spec.Components),
			levels(spec),
			code(spec.Required),
			escape(spec.Summary),
		)
	}

	return b.String()
}

// levels names the level an event is emitted at, and the alternatives its
// entry allows for an event whose severity depends on the outcome.
func levels(spec logging.EventSpec) string {
	out := []string{escape(spec.Level.String())}
	for _, l := range spec.AllowedLevels {
		out = append(out, escape(l.String()))
	}
	return strings.Join(out, " or ")
}

func components(cs []logging.Component) string {
	if len(cs) == 0 {
		return "any"
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, "`"+escape(string(c))+"`")
	}
	return strings.Join(out, ", ")
}

func code(fields []string) string {
	if len(fields) == 0 {
		return "none"
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, "`"+escape(f)+"`")
	}
	return strings.Join(out, ", ")
}

// escape keeps a cell on one row: a bare pipe would split it, a newline would
// end the table.
func escape(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}
