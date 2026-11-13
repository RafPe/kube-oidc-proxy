// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
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
// Each WarningKey gets its own bucket, so a flood of one kind of anomaly
// cannot hide the first occurrence of another. What was dropped is reported
// rather than lost: Flush emits one log.warning.suppressed summary per key
// that dropped records since the previous flush.
//
// The clock is injected so a test can reason about the bucket without
// sleeping.
type Limiter struct {
	limit        rate.Limit
	burst        int
	summaryEvery time.Duration
	clock        func() time.Time

	mu      sync.Mutex
	entries map[WarningKey]*limiterEntry
}

// WarningKey names one bucket: the warning record it limits and the reason the
// summary reports as warning_reason. For a record that carries a reason field
// it is that reason; a record without one names its bucket instead. Keyed by
// the record as well as the reason, so the summary also reports which event
// was dropped.
type WarningKey struct {
	Event  EventType
	Reason string
}

// limiterEntry is the bucket and the drop count for one key. The bucket
// outlives a flush; only the count is reset, so a flush cannot hand a caller a
// fresh burst.
type limiterEntry struct {
	limiter *rate.Limiter
	dropped int
}

// NewLimiter returns a Limiter admitting ratePerSecond records per second per
// key with the given burst, and summarising what it dropped every
// summaryEvery. The rate is a plain float64 so a caller does not have to know
// which bucket implementation backs it; it is converted internally. A nil
// clock means time.Now.
func NewLimiter(ratePerSecond float64, burst int, summaryEvery time.Duration, clock func() time.Time) *Limiter {
	if clock == nil {
		clock = time.Now
	}
	return &Limiter{
		limit:        rate.Limit(ratePerSecond),
		burst:        burst,
		summaryEvery: summaryEvery,
		clock:        clock,
		entries:      make(map[WarningKey]*limiterEntry),
	}
}

// Allow reports whether the warning record key names may be emitted now,
// counting the record when it may not.
func (l *Limiter) Allow(key WarningKey) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.entries[key]
	if !ok {
		entry = &limiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = entry
	}

	if entry.limiter.AllowN(l.clock(), 1) {
		return true
	}

	entry.dropped++

	return false
}

// Flush emits one log.warning.suppressed record per key that dropped warnings
// since the previous flush and resets those counts. A key that dropped
// nothing produces no record, so a quiet proxy stays quiet.
func (l *Limiter) Flush(ctx context.Context, logger *slog.Logger) {
	for _, s := range l.drain() {
		Emit(ctx, logger, EventLogWarningSuppressed,
			slog.String("suppressed_event_type", string(s.key.Event)),
			slog.String("warning_reason", Sanitize(s.key.Reason)),
			slog.Int("suppressed_count", s.dropped),
			slog.Int("interval_seconds", int(l.summaryEvery.Seconds())))
	}
}

// suppressed is one key's drop count as of a flush.
type suppressed struct {
	key     WarningKey
	dropped int
}

// drain returns the keys that dropped records and zeroes their counts, sorted
// so a flush emits its summaries in a stable order rather than in Go's
// randomised map order. The lock is not held while records are emitted.
func (l *Limiter) drain() []suppressed {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []suppressed
	for key, entry := range l.entries {
		if entry.dropped == 0 {
			continue
		}
		out = append(out, suppressed{key: key, dropped: entry.dropped})
		entry.dropped = 0
	}
	slices.SortFunc(out, func(a, b suppressed) int {
		return cmp.Or(cmp.Compare(a.key.Event, b.key.Event), cmp.Compare(a.key.Reason, b.key.Reason))
	})

	return out
}
