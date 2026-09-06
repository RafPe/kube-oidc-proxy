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

	"github.com/pmezard/go-difflib/difflib"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics"
)

const (
	docPath     = "docs/metrics.md"
	beginMarker = "<!-- metrics:begin -->"
	endMarker   = "<!-- metrics:end -->"

	skeleton = `# Metrics

` + beginMarker + `
` + endMarker + `
`
)

func main() {
	check := flag.Bool("check", false, "report a diff and exit 1 instead of writing")
	flag.Parse()

	if err := run(*check); err != nil {
		fmt.Fprintf(os.Stderr, "metricdoc: %v\n", err)
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
		diff, err := unifiedDiff(string(current), want)
		if err != nil {
			return err
		}
		return fmt.Errorf("%s is out of date: run `make metricdoc` and commit the result\n\n%s", docPath, diff)
	}
	// docPath is a compile-time constant relative to the repository root, so
	// gosec's G703 taint warning here has no reachable attacker input.
	return os.WriteFile(docPath, []byte(want), 0600) //nolint:gosec // constant path, no user input
}

// unifiedDiff renders the change -check would have written, so the failure
// names the drifted rows instead of only reporting staleness.
func unifiedDiff(current, want string) (string, error) {
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(current),
		B:        difflib.SplitLines(want),
		FromFile: docPath,
		FromDate: "committed",
		ToFile:   docPath,
		ToDate:   "generated",
		Context:  3,
	})
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

func renderTable() string {
	var b strings.Builder
	b.WriteString("| name | type | labels | stability | help |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, s := range metrics.Catalogue() {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
			escape(s.Name), s.Type, labels(s.Labels), s.Stability, escape(s.Help))
	}
	return b.String()
}

func labels(ls []string) string {
	if len(ls) == 0 {
		return "none"
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, "`"+escape(l)+"`")
	}
	return strings.Join(out, ", ")
}

// escape keeps a cell on one row: a bare pipe would split it, a newline would
// end the table.
func escape(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}
