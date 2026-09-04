// Copyright Jetstack Ltd. See LICENSE for details.
package helper

import (
	"strings"
	"testing"
)

// The proxy's contract is one JSON object per line. A line that does not decode
// has to be reported, not skipped: a skipped line disappears from the decoded
// set, so every assertion made against that set passes for a stream that
// violates the contract.
func TestDecodeRecordsReportsTheFirstUndecodableLine(t *testing.T) {
	raw := strings.Join([]string{
		`{"event_type":"proxy.config.loaded","schema_version":1}`,
		`{invalid`,
		`{"event_type":"readiness.proxy.ready","schema_version":1}`,
	}, "\n")

	records, err := decodeRecords(raw)
	if err == nil {
		t.Fatalf("decodeRecords accepted a malformed line, got=%d records and no error", len(records))
	}
	if records != nil {
		t.Errorf("decodeRecords returned records alongside an error: %v", records)
	}
	if got := err.Error(); !strings.Contains(got, "line 2") {
		t.Errorf("error does not name the offending line number: %q", got)
	}
	if got := err.Error(); !strings.Contains(got, "{invalid") {
		t.Errorf("error does not quote the offending line: %q", got)
	}
}

// A line that is valid JSON but not an object is just as much a contract
// violation as one that is not JSON at all.
func TestDecodeRecordsRejectsANonObjectLine(t *testing.T) {
	raw := `{"schema_version":1}` + "\n" + `["not","an","object"]`

	if _, err := decodeRecords(raw); err == nil {
		t.Fatal("decodeRecords accepted a JSON array as a record")
	}
}

// A "null" line is the trap case: unmarshalling JSON null into a map succeeds
// and leaves the map nil, so without an explicit check it becomes an empty
// record rather than an error.
func TestDecodeRecordsRejectsANullLine(t *testing.T) {
	raw := `{"schema_version":1}` + "\n" + `null`

	records, err := decodeRecords(raw)
	if err == nil {
		t.Fatalf("decodeRecords accepted a JSON null line, got=%d records: %v", len(records), records)
	}
	if got := err.Error(); !strings.Contains(got, "line 2") {
		t.Errorf("error does not name the offending line number: %q", got)
	}
}

// Blank lines are framing, not records: a log stream ends with a newline.
func TestDecodeRecordsSkipsBlankLinesAndDecodesTheRest(t *testing.T) {
	raw := `{"event_type":"proxy.config.loaded"}` + "\n\n" + `{"event_type":"readiness.proxy.ready"}` + "\n"

	records, err := decodeRecords(raw)
	if err != nil {
		t.Fatalf("decodeRecords rejected a well-formed stream: %s", err)
	}
	if len(records) != 2 {
		t.Fatalf("decoded %d records, want 2: %v", len(records), records)
	}
	if got := records[1]["event_type"]; got != "readiness.proxy.ready" {
		t.Errorf("second record: got=%v want=readiness.proxy.ready", got)
	}
}
