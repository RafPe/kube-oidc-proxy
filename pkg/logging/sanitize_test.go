// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"strings"
	"testing"
)

func TestBound(t *testing.T) {
	if got := Bound("a\nb\x00c", 10); got != "a bc" {
		t.Fatalf("Bound = %q", got)
	}
	if got := Bound(strings.Repeat("x", 100), 5); got != "xxxxx" {
		t.Fatalf("Bound truncation = %q", got)
	}
}

func TestBoundedList(t *testing.T) {
	out, omitted := BoundedList([]string{"a", "b", "c"}, 2)
	if len(out) != 2 || omitted != 1 {
		t.Fatalf("got %v omitted=%d", out, omitted)
	}
}

func TestSanitizeList(t *testing.T) {
	got := SanitizeList([]string{"dev", "bad\ngroup"})
	if len(got) != 2 || got[0] != "dev" || got[1] != "bad group" {
		t.Fatalf("SanitizeList = %q", got)
	}
	// No cap: a list far longer than MaxGroups is kept whole.
	in := make([]string, MaxGroups+8)
	for i := range in {
		in[i] = "g"
	}
	if got := SanitizeList(in); len(got) != len(in) {
		t.Fatalf("SanitizeList capped %d entries to %d", len(in), len(got))
	}
	if got := SanitizeList(nil); got != nil {
		t.Fatalf("SanitizeList(nil) = %v, want nil", got)
	}
}
