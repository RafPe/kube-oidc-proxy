// Copyright Jetstack Ltd. See LICENSE for details.

package logging_test

import (
	"context"
	"testing"
	"time"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

func TestLimiterAllowsBurstThenSummarises(t *testing.T) {
	now := time.Unix(0, 0)
	l := logging.NewLimiter(1, 3, time.Minute, func() time.Time { return now })
	allowed := 0
	for i := 0; i < 10; i++ {
		if l.Allow("reserved_identity") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("allowed %d, want burst of 3", allowed)
	}
	root, cap := logtest.New(t, 0)
	l.Flush(context.Background(), root)
	rec := cap.Only(t, logging.EventLogWarningSuppressed)
	if n, _ := rec.Int("suppressed_count"); n != 7 || rec.String("warning_reason") != "reserved_identity" {
		t.Fatalf("%v", rec)
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

	if !l.Allow("reserved_identity") {
		t.Fatal("the first record was refused with a burst of 1")
	}
	if l.Allow("reserved_identity") {
		t.Fatal("a second record was allowed before the bucket refilled")
	}

	now = now.Add(500 * time.Millisecond)
	if !l.Allow("reserved_identity") {
		t.Fatal("no token half a second after a two-per-second bucket was spent")
	}
}
