// Copyright Jetstack Ltd. See LICENSE for details.
package docsync

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func section(t *testing.T) Section {
	t.Helper()
	return Section{
		Path:       filepath.Join(t.TempDir(), "doc.md"),
		Begin:      "<!-- rows:begin -->",
		End:        "<!-- rows:end -->",
		Title:      "Rows",
		MakeTarget: "rowdoc",
	}
}

func TestSyncCreatesDocumentFromSkeleton(t *testing.T) {
	s := section(t)

	if err := Sync(s, "| a |\n", false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	got, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Rows\n\n<!-- rows:begin -->\n| a |\n<!-- rows:end -->\n"
	if string(got) != want {
		t.Fatalf("document = %q, want %q", got, want)
	}
}

func TestSyncKeepsProseOutsideTheMarkers(t *testing.T) {
	s := section(t)
	doc := "# Rows\n\nIntro kept.\n\n<!-- rows:begin -->\n| stale |\n<!-- rows:end -->\n\nOutro kept.\n"
	if err := os.WriteFile(s.Path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Sync(s, "| fresh |\n", false); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	got, err := os.ReadFile(s.Path)
	if err != nil {
		t.Fatal(err)
	}
	want := "# Rows\n\nIntro kept.\n\n<!-- rows:begin -->\n| fresh |\n<!-- rows:end -->\n\nOutro kept.\n"
	if string(got) != want {
		t.Fatalf("document = %q, want %q", got, want)
	}
}

func TestSyncCheckReportsDiffWithoutWriting(t *testing.T) {
	s := section(t)
	doc := "# Rows\n\n<!-- rows:begin -->\n| stale |\n<!-- rows:end -->\n"
	if err := os.WriteFile(s.Path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}

	err := Sync(s, "| fresh |\n", true)
	if err == nil {
		t.Fatal("Sync(check) = nil error, want stale report")
	}
	for _, want := range []string{"out of date", "make rowdoc", "-| stale |", "+| fresh |"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	got, readErr := os.ReadFile(s.Path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(got) != doc {
		t.Fatalf("check rewrote the document: %q", got)
	}
}

func TestSyncCheckPassesOnCurrentDocument(t *testing.T) {
	s := section(t)
	doc := "# Rows\n\n<!-- rows:begin -->\n| same |\n<!-- rows:end -->\n"
	if err := os.WriteFile(s.Path, []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}

	if err := Sync(s, "| same |\n", true); err != nil {
		t.Fatalf("Sync(check) on a current document = %v, want nil", err)
	}
}

func TestSyncRefusesDocumentWithoutMarkers(t *testing.T) {
	tests := map[string]string{
		"no begin":         "# Rows\n<!-- rows:end -->\n",
		"no end":           "# Rows\n<!-- rows:begin -->\n",
		"end before begin": "# Rows\n<!-- rows:end -->\n<!-- rows:begin -->\n",
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			s := section(t)
			if err := os.WriteFile(s.Path, []byte(doc), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Sync(s, "| a |\n", false); err == nil {
				t.Fatal("Sync() = nil error, want marker error")
			}
		})
	}
}

func TestEscapeKeepsCellOnOneRow(t *testing.T) {
	if got := Escape("a|b\nc"); got != `a\|b c` {
		t.Fatalf("Escape = %q", got)
	}
}

func TestCodeList(t *testing.T) {
	if got := CodeList(nil); got != "none" {
		t.Fatalf("CodeList(nil) = %q", got)
	}
	if got := CodeList([]string{"a", "b|c"}); got != "`a`, `b\\|c`" {
		t.Fatalf("CodeList = %q", got)
	}
}
