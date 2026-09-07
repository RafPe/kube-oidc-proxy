// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import "time"

// ReviewRequest counts and times one review API call actually issued to the
// API server. It is called at the Create call site, never at a caller that
// may have been served from the cache or from a coalesced in-flight call, so
// the count is the number of round trips the API server saw.
func (r *Recorder) ReviewRequest(review Review, outcome ReviewOutcome, d time.Duration) {
	if r == nil {
		return
	}
	labels := []string{projectReview(review), projectReviewOutcome(outcome)}
	r.reviewRequests.WithLabelValues(labels...).Inc()
	r.reviewDuration.WithLabelValues(labels...).Observe(d.Seconds())
}

// CacheLookup counts one review-cache consultation.
func (r *Recorder) CacheLookup(review Review, result CacheResult) {
	if r == nil {
		return
	}
	r.cacheLookups.WithLabelValues(projectReview(review), projectCacheResult(result)).Inc()
}
