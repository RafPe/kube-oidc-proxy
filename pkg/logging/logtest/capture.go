// Copyright Jetstack Ltd. See LICENSE for details.

// Package logtest captures the records a test produces so assertions can be
// made on the structured fields themselves rather than on formatted text.
package logtest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// Record is one decoded JSON record.
type Record map[string]any

// Capture is the in-memory destination of a test logger. It is safe for
// concurrent use: the proxy logs from many goroutines.
type Capture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write implements io.Writer for the JSON handler behind the test logger.
func (c *Capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// New returns a root logger at the level the given -v verbosity selects,
// writing JSON into the returned Capture.
func New(t testing.TB, verbosity int) (*slog.Logger, *Capture) {
	t.Helper()
	c := &Capture{}
	l, err := logging.New(logging.Options{Format: logging.FormatJSON, Verbosity: verbosity, Output: c})
	if err != nil {
		t.Fatalf("logtest.New: %v", err)
	}
	return l, c
}

// Raw returns the captured output verbatim, for "must not contain"
// assertions on secrets.
func (c *Capture) Raw() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// Records decodes every captured line. A line that is not valid JSON is
// skipped: the caller asserts on Raw for those.
func (c *Capture) Records() []Record {
	var out []Record
	for _, line := range strings.Split(c.Raw(), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// ByEvent returns the captured records carrying the given event_type.
func (c *Capture) ByEvent(e logging.EventType) []Record {
	var out []Record
	for _, rec := range c.Records() {
		if rec.String("event_type") == string(e) {
			out = append(out, rec)
		}
	}
	return out
}

// Only returns the single record for the given event type and fails the test
// when there is not exactly one.
func (c *Capture) Only(t testing.TB, e logging.EventType) Record {
	t.Helper()
	recs := c.ByEvent(e)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 %s record, got %d: %s", e, len(recs), c.Raw())
	}
	return recs[0]
}

// String returns the value of key as a string, or "" when it is absent or not
// a string.
func (r Record) String(key string) string {
	s, _ := r[key].(string)
	return s
}

// Int returns the value of key as an int. JSON numbers decode as float64; the
// bool reports whether the key was present and numeric.
func (r Record) Int(key string) (int, bool) {
	switch v := r[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case json.Number:
		n, err := v.Int64()
		return int(n), err == nil
	default:
		return 0, false
	}
}
