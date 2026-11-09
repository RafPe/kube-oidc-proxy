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

func TestSanitize(t *testing.T) {
	tests := map[string]struct{ in, exp string }{
		"plain":            {"alice@example.com", "alice@example.com"},
		"newline to space": {"a\nb", "a b"},
		"crlf to spaces":   {"a\r\nb", "a  b"},
		"tab to space":     {"a\tb", "a b"},
		"drops control":    {"a\x00\x1bb", "ab"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.exp {
				t.Errorf("Sanitize(%q) = %q, want %q", tc.in, got, tc.exp)
			}
		})
	}
}
