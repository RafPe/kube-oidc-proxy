// Copyright Jetstack Ltd. See LICENSE for details.

package logging_test

import (
	"context"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// reservedIdentityKey is a bucket for a warning that carries a reason.
var reservedIdentityKey = logging.WarningKey{Event: logging.EventRequestAnomalyDetected, Reason: "reserved_identity"}

func TestLimiterAllowsBurstThenSummarises(t *testing.T) {
	now := time.Unix(0, 0)
	l := logging.NewLimiter(1, 3, time.Minute, func() time.Time { return now })
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow(reservedIdentityKey) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d, want burst of 3", allowed)
	}
	root, cap := logtest.New(t, 0)
	l.Flush(context.Background(), root)
	rec := cap.Only(t, logging.EventLogWarningSuppressed)
	if n, _ := rec.Int("suppressed_count"); n != 7 || rec.String("warning_reason") != "reserved_identity" ||
		rec.String("suppressed_event_type") != string(logging.EventRequestAnomalyDetected) {
		t.Fatalf("%v", rec)
	}
	// The summary names the window it covers, so a count is readable without
	// knowing how the proxy was configured.
	if n, _ := rec.Int("interval_seconds"); n != 60 {
		t.Fatalf("interval_seconds = %d, want 60", n)
	}
	l.Flush(context.Background(), root)
	if len(cap.ByEvent(logging.EventLogWarningSuppressed)) != 1 {
		t.Fatal("flush with nothing suppressed emitted a summary")
	}
}

// TestLimiterRefillsAtTheConfiguredRatePerSecond pins the unit and the type of
// the first parameter: it is a float64 count of records per second, so a
// caller holding a rate does not have to know the bucket implementation.
func TestLimiterRefillsAtTheConfiguredRatePerSecond(t *testing.T) {
	var ratePerSecond float64 = 2
	now := time.Unix(0, 0)
	l := logging.NewLimiter(ratePerSecond, 1, time.Minute, func() time.Time { return now })

	if !l.Allow(reservedIdentityKey) {
		t.Fatal("the first record was refused with a burst of 1")
	}
	if l.Allow(reservedIdentityKey) {
		t.Fatal("a second record was allowed before the bucket refilled")
	}

	now = now.Add(500 * time.Millisecond)
	if !l.Allow(reservedIdentityKey) {
		t.Fatal("no token half a second after a two-per-second bucket was spent")
	}
}

// TestLimiterKeepsKeysApart pins that two keys never share a bucket and that
// the summary names both the event and the key's reason.
func TestLimiterKeepsKeysApart(t *testing.T) {
	now := time.Unix(0, 0)
	l := logging.NewLimiter(1, 1, time.Minute, func() time.Time { return now })
	dropped := logging.WarningKey{Event: logging.EventRequestHeadersDropped, Reason: "headers_dropped"}

	for _, key := range []logging.WarningKey{dropped, reservedIdentityKey} {
		if !l.Allow(key) {
			t.Fatalf("first record for %+v refused: buckets are shared", key)
		}
	}
	l.Allow(dropped)

	root, cap := logtest.New(t, 0)
	l.Flush(context.Background(), root)
	rec := cap.Only(t, logging.EventLogWarningSuppressed)
	if rec.String("suppressed_event_type") != string(logging.EventRequestHeadersDropped) {
		t.Fatalf("suppressed_event_type = %q", rec.String("suppressed_event_type"))
	}
	if rec.String("warning_reason") != "headers_dropped" {
		t.Fatalf("warning_reason = %q, want headers_dropped", rec.String("warning_reason"))
	}
}

// TestLimiterRunFlushesOnItsOwnCadenceAndOnShutdown covers both halves of
// Run: a summary every summaryEvery while it runs, and a final one when ctx
// ends, so a burst suppressed just before shutdown is still accounted for.
func TestLimiterRunFlushesOnItsOwnCadenceAndOnShutdown(t *testing.T) {
	now := time.Unix(0, 0)
	l := logging.NewLimiter(1, 1, 10*time.Millisecond, func() time.Time { return now })
	root, cap := logtest.New(t, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		l.Run(ctx, root)
	}()

	l.Allow(reservedIdentityKey)
	l.Allow(reservedIdentityKey)
	deadline := time.Now().Add(5 * time.Second)
	for len(cap.ByEvent(logging.EventLogWarningSuppressed)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run emitted no summary within 5s of a 10ms cadence")
		}
		time.Sleep(time.Millisecond)
	}

	l.Allow(reservedIdentityKey)
	cancel()
	<-done

	recs := cap.ByEvent(logging.EventLogWarningSuppressed)
	if len(recs) != 2 {
		t.Fatalf("summaries = %d, want 2 (one on the tick, one on shutdown): %s", len(recs), cap.Raw())
	}
	for _, rec := range recs {
		if n, _ := rec.Int("suppressed_count"); n != 1 {
			t.Errorf("suppressed_count = %d, want 1: %v", n, rec)
		}
	}
}
