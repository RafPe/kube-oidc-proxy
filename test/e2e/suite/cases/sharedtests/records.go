// Copyright Jetstack Ltd. See LICENSE for details.
package sharedtests

// The proxy's structured log stream is read by more than one case: the logging
// case asserts the contract itself, and the audit and reserved-identity cases
// join their own observations to it. The filters live here, exported, because
// that is the only way a case package can reach a helper written in another
// one; they take the decoded records a caller got from
// helper.ProxyLogRecords.

// ByEvent returns the records carrying the given event_type.
func ByEvent(recs []map[string]any, eventType string) []map[string]any {
	return filter(recs, "event_type", eventType)
}

// ByComponent returns the records carrying the given component.
func ByComponent(recs []map[string]any, component string) []map[string]any {
	return filter(recs, "component", component)
}

// WithRequestID returns the records carrying the given request_id.
func WithRequestID(recs []map[string]any, id string) []map[string]any {
	return filter(recs, "request_id", id)
}

// filter returns the records whose key holds want. An empty want would match
// every record that omits the key, so it never matches anything.
func filter(recs []map[string]any, key, want string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if got, ok := r[key].(string); ok && want != "" && got == want {
			out = append(out, r)
		}
	}

	return out
}
