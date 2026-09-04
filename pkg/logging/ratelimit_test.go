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
