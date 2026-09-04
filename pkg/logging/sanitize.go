// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"log/slog"
	"strings"
	"unicode"
)

// Bounds for user-influenced values. Every string that reaches a record from a
// request, a token or a configuration file is truncated to one of these so a
// hostile peer cannot inflate the log stream.
const (
	MaxRequestID    = 64
	MaxErrorMessage = 512
	MaxIdentity     = 256
	MaxGroups       = 32
)

// Sanitize removes control characters from a user-controlled string so that
// values cannot inject newlines or terminal escapes into the log stream. Tabs,
// carriage returns and newlines collapse to a single space; other control
// runes are dropped.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', '\t':
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// Bound sanitizes a string and truncates it to max runes. A max of zero or
// less leaves the length untouched.
func Bound(s string, max int) string {
	s = Sanitize(s)
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// BoundedList sanitizes every element of a slice, bounds each to MaxIdentity
// (its elements are identity strings: group names, extras values) and keeps at
// most max of them. It returns the kept elements and the number omitted, so
// callers can report the drop rather than hide it. An empty input yields a nil
// slice, keeping the field absent rather than empty in the record.
func BoundedList(in []string, max int) (out []string, omitted int) {
	if len(in) == 0 {
		return nil, 0
	}
	kept := len(in)
	if max > 0 && kept > max {
		kept = max
	}
	out = make([]string, kept)
	for i := 0; i < kept; i++ {
		out[i] = Bound(in[i], MaxIdentity)
	}
	return out, len(in) - kept
}

// ErrAttr renders an error as the standard bounded error_message field. A nil
// error yields an empty value rather than panicking at the call site.
func ErrAttr(err error) slog.Attr {
	if err == nil {
		return slog.String("error_message", "")
	}
	return slog.String("error_message", Bound(err.Error(), MaxErrorMessage))
}
