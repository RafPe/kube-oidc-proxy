// Copyright Jetstack Ltd. See LICENSE for details.

// Package docsync keeps a generated markdown table inside a hand-written
// document. The document owns everything outside a pair of HTML-comment
// markers; the generator owns everything between them. Each hack/*doc command
// renders its table and hands it here, so the write-or-check behaviour and
// the diff a stale file reports are the same for every generated section.
package docsync

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
)

// Main is the whole of a doc-generating command: it parses the -check flag,
// renders the table and syncs the section, reporting a failure under name and
// exiting non-zero so CI fails on a stale document.
func Main(name string, s Section, render func() string) {
	check := flag.Bool("check", false, "report a diff and exit 1 instead of writing")
	flag.Parse()

	if err := Sync(s, render(), *check); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
		os.Exit(1)
	}
}

// Section names the document and the markers a generated table lives between.
type Section struct {
	// Path is the document, relative to the repository root the command runs
	// from.
	Path string

	// Begin and End are the marker comments that delimit the generated table.
	Begin, End string

	// Title heads the document the first run creates when Path does not exist.
	Title string

	// MakeTarget is the target a stale -check run tells the operator to run.
	MakeTarget string
}

// skeleton is the document created when Path does not exist yet: a title and
// an empty generated section for the table to land in.
func (s Section) skeleton() string {
	return "# " + s.Title + "\n\n" + s.Begin + "\n" + s.End + "\n"
}

// Sync writes table into the section, or with check set reports how the
// committed document differs from what would be written and returns an error
// so CI fails on a stale file. A document that is already current is left
// alone either way.
func Sync(s Section, table string, check bool) error {
	current, err := os.ReadFile(s.Path)
	switch {
	case os.IsNotExist(err):
		current = []byte(s.skeleton())
	case err != nil:
		return err
	}

	want, err := s.replace(string(current), table)
	if err != nil {
		return err
	}

	if want == string(current) {
		return nil
	}
	if check {
		diff, err := s.unifiedDiff(string(current), want)
		if err != nil {
			return err
		}
		return fmt.Errorf("%s is out of date: run `make %s` and commit the result\n\n%s", s.Path, s.MakeTarget, diff)
	}
	// Path is a compile-time constant in every caller, relative to the
	// repository root, so gosec's G703 taint warning has no reachable attacker
	// input.
	return os.WriteFile(s.Path, []byte(want), 0600) //nolint:gosec // constant path, no user input
}

// unifiedDiff renders the change -check would have written, so the failure
// names the drifted rows instead of only reporting staleness.
func (s Section) unifiedDiff(current, want string) (string, error) {
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(current),
		B:        difflib.SplitLines(want),
		FromFile: s.Path,
		FromDate: "committed",
		ToFile:   s.Path,
		ToDate:   "generated",
		Context:  3,
	})
}

// replace swaps the text between the two markers for table, keeping everything
// outside them untouched.
func (s Section) replace(doc, table string) (string, error) {
	begin := strings.Index(doc, s.Begin)
	if begin < 0 {
		return "", fmt.Errorf("%s does not contain %s", s.Path, s.Begin)
	}
	end := strings.Index(doc, s.End)
	if end < 0 {
		return "", fmt.Errorf("%s does not contain %s", s.Path, s.End)
	}
	if end < begin {
		return "", fmt.Errorf("%s has %s before %s", s.Path, s.End, s.Begin)
	}
	return doc[:begin+len(s.Begin)] + "\n" + table + doc[end:], nil
}

// Escape keeps a cell on one row of a markdown table: a bare pipe would split
// it, a newline would end the table.
func Escape(s string) string {
	s = strings.ReplaceAll(s, "|", `\|`)
	return strings.ReplaceAll(s, "\n", " ")
}

// CodeList renders items as a comma-separated list of inline code spans, or
// "none" when there are none, which is how every generated table shows a
// set-valued column.
func CodeList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, "`"+Escape(item)+"`")
	}
	return strings.Join(out, ", ")
}
