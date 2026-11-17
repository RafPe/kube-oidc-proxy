// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"errors"
	"testing"
)

// TestCoalescingVerdict pins what the coalescing scenario is allowed to accept
// as evidence. Counting reviews against calls is not enough: a burst answered
// by one cold live review and seven ordinary cache hits produces exactly the
// same "fewer reviews than calls" as a burst of eight concurrent misses that
// shared one flight, and only the second proves anything. The deltas below are
// the ones a real run reports; the negative cases are the ones the old rule
// waved through.
func TestCoalescingVerdict(t *testing.T) {
	const calls = 8

	tests := map[string]struct {
		allowed, misses, reviews float64
		wantErr                  bool
		wantRetryable            bool
	}{
		"eight concurrent misses sharing one review": {
			allowed: 8, misses: 8, reviews: 1,
		},
		"eight concurrent misses sharing three reviews": {
			allowed: 8, misses: 8, reviews: 3,
		},
		"one cold miss and seven cache hits": {
			allowed: 8, misses: 1, reviews: 1,
			wantErr: true, wantRetryable: true,
		},
		"every call served from the cache": {
			allowed: 8, misses: 0, reviews: 0,
			wantErr: true, wantRetryable: true,
		},
		"calls spaced out, so every miss issued its own review": {
			allowed: 8, misses: 8, reviews: 8,
			wantErr: true,
		},
		"more reviews than misses": {
			allowed: 8, misses: 3, reviews: 5,
			wantErr: true,
		},
		"misses that issued no review at all": {
			allowed: 8, misses: 4, reviews: 0,
			wantErr: true,
		},
		"a call that was not allowed": {
			allowed: 7, misses: 8, reviews: 1,
			wantErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := coalescingVerdict("kop-0", calls, test.allowed, test.misses, test.reviews)
			switch {
			case test.wantErr && err == nil:
				t.Fatalf("coalescingVerdict(allowed=%.0f, misses=%.0f, reviews=%.0f) = nil, want an error",
					test.allowed, test.misses, test.reviews)
			case !test.wantErr && err != nil:
				t.Fatalf("coalescingVerdict(allowed=%.0f, misses=%.0f, reviews=%.0f) = %v, want nil",
					test.allowed, test.misses, test.reviews, err)
			}
			if got := errors.Is(err, errNoConcurrentMiss); got != test.wantRetryable {
				t.Fatalf("errors.Is(%v, errNoConcurrentMiss) = %t, want %t", err, got, test.wantRetryable)
			}
		})
	}
}
