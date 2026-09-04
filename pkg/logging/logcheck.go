// Copyright Jetstack Ltd. See LICENSE for details.

//go:build logcheck

package logging

import (
	"fmt"
	"log/slog"
	"strings"
)

// checkRequired panics when a record is missing an attribute its registry
// entry declares as required. It is compiled in only under -tags logcheck, the
// tag every test run sets, so a call site that forgets a mandatory field fails
// a test rather than shipping an unqueryable record. Production builds carry
// the no-op in logcheck_off.go and pay nothing.
//
// Only the attributes passed to Emit are inspected: attributes bound to the
// logger with With are invisible to this check.
func checkRequired(e EventType, spec EventSpec, attrs []slog.Attr) {
	for _, key := range spec.Required {
		if !hasNonEmpty(attrs, key) {
			panic(fmt.Sprintf("logging: event %s is missing required attribute %q", e, key))
		}
	}
}

// hasNonEmpty reports whether attrs carries key with a value that is neither
// absent nor an empty string.
func hasNonEmpty(attrs []slog.Attr, key string) bool {
	for _, a := range attrs {
		if a.Key != key {
			continue
		}
		v := a.Value.Resolve()
		if v.Kind() == slog.KindString {
			return strings.TrimSpace(v.String()) != ""
		}
		return true
	}
	return false
}
