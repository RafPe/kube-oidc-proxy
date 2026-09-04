// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter token-buckets the warning records a single hostile or misconfigured
// client can otherwise produce without bound. It is deliberately narrow: only
// request.anomaly.detected and request.headers.dropped are limited, never an
// access decision, so a denial is always recorded even while the anomaly that
// explains it is being sampled.
//
// Each reason gets its own bucket, so a flood of one kind of anomaly cannot
// hide the first occurrence of another. What was dropped is reported rather
// than lost: Flush emits one log.warning.suppressed summary per reason that
// dropped records since the previous flush.
//
// The clock is injected so a test can reason about the bucket without
// sleeping. A nil Limiter allows everything: a partially wired caller must
// never silence a warning, because WARN and ERROR are never hidden.
type Limiter struct {
	limit    rate.Limit
	burst    int
	interval time.Duration
	clock    func() time.Time

	mu      sync.Mutex
	entries map[string]*limiterEntry
}

// limiterEntry is the bucket and the drop count for one reason. The bucket
// outlives a flush; only the count is reset, so a flush cannot hand a caller a
// fresh burst.
type limiterEntry struct {
	limiter *rate.Limiter
	dropped int
}

// NewLimiter returns a Limiter admitting limit records per second per reason
// with the given burst, and summarising what it dropped every interval. A nil
// clock means time.Now.
func NewLimiter(limit rate.Limit, burst int, interval time.Duration, clock func() time.Time) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{
		limit:    limit,
		burst:    burst,
		interval: interval,
		clock:    clock,
		entries:  make(map[string]*limiterEntry),
	}
}

// Allow reports whether a warning carrying the given reason may be emitted
// now, counting the record when it may not.
func (l *Limiter) Allow(reason string) bool {
	if l == nil {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[reason]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[reason] = entry
	}

	if entry.limiter.AllowN(l.clock(), 1) {
		return true
	}

	entry.dropped++

	return false
}

// Flush emits one log.warning.suppressed record per reason that dropped
// warnings since the previous flush and resets those counts. A reason that
// dropped nothing produces no record, so a quiet proxy stays quiet.
func (l *Limiter) Flush(ctx context.Context, logger *slog.Logger) {
	if l == nil || logger == nil {
		return
	}

	for _, s := range l.drain() {
		Emit(ctx, logger, EventLogWarningSuppressed,
			slog.String("warning_reason", Sanitize(s.reason)),
			slog.Int("suppressed_count", s.dropped),
			slog.Int("interval_seconds", int(l.interval.Seconds())))
	}
}

// suppressed is one reason's drop count as of a flush.
type suppressed struct {
	reason  string
	dropped int
}

// drain returns the reasons that dropped records and zeroes their counts,
// sorted so a flush emits its summaries in a stable order rather than in Go's
// randomised map order. The lock is not held while records are emitted.
func (l *Limiter) drain() []suppressed {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []suppressed
	for reason, entry := range l.entries {
		if entry.dropped == 0 {
			continue
		}
		out = append(out, suppressed{reason: reason, dropped: entry.dropped})
		entry.dropped = 0
	}
	sort.Slice(out, func(i, j int) bool { return out[i].reason < out[j].reason })

	return out
}
