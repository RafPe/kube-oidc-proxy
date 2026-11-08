// Copyright Jetstack Ltd. See LICENSE for details.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// coalescedImpersonation fires coalesceCalls identical impersonation requests
// at one replica whose decision cache has just expired, and asserts that they
// shared SubjectAccessReviews. This is the property that keeps a thundering
// herd of clients from becoming a thundering herd of SubjectAccessReviews
// against the API server.
//
// The burst is released from a barrier rather than merely started in
// goroutines: goroutines guarantee only that the client sent the calls, and
// the proxy can still finish one before the next arrives, in which case seven
// of the eight are cache hits and nothing was shared. Whether they really
// overlapped is read back from the replica's own counters, and a run that did
// not overlap is retried rather than failed - it was mistimed, not wrong.
func (g *generator) coalescedImpersonation(ctx context.Context) []result {
	token, err := g.validToken()
	if err != nil {
		return failed("impersonation_coalesced", err)
	}

	var results []result
	for attempt := 1; ; attempt++ {
		results, err = g.coalesceBurst(ctx, attempt, token)
		if err == nil || !errors.Is(err, errNoConcurrentMiss) || attempt == coalesceAttempts {
			break
		}
	}
	if err != nil && len(results) > 0 {
		// Only the last attempt's results are returned, so --once sees one
		// set of scenario names and one verdict rather than a mixture.
		results[0].err = err
	}

	return results
}

// coalesceBurst runs one attempt: wait the cache out, release coalesceCalls
// identical calls together, and read the verdict off the replica's counters.
// The results it returns are the calls this attempt made.
func (g *generator) coalesceBurst(ctx context.Context, attempt int, token string) ([]result, error) {
	// The cache is what would otherwise answer these calls, and a cached
	// decision never reaches the flight group at all.
	select {
	case <-ctx.Done():
		return failed("impersonation_coalesced", ctx.Err()), nil
	case <-time.After(sarCacheTTL + time.Second):
	}

	before, err := g.scrape(ctx)
	if err != nil {
		return failed("impersonation_coalesced", err), nil
	}

	headers := http.Header{"Impersonate-User": []string{impersonated}}
	// One slot per call, written only by the goroutine that owns it, so the
	// results stay in call order and nothing is shared but the slice header.
	results := make([]result, coalesceCalls)
	// Every caller announces itself on ready and then blocks on release, so
	// the requests leave together instead of trailing the goroutine that
	// started them.
	ready := make(chan struct{}, coalesceCalls)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < coalesceCalls; i++ {
		wg.Go(func() {
			ready <- struct{}{}
			<-release
			results[i] = g.observe(ctx, fmt.Sprintf("impersonation_coalesced[%d/%d]", i+1, coalesceCalls),
				http.StatusOK, func(ctx context.Context) (int, error) {
					return g.doAt(ctx, g.pinned.proxy.URL(), http.MethodGet,
						fmt.Sprintf("/api/v1/namespaces/%s/pods", g.namespace), token, headers)
				})
		})
	}
	for i := 0; i < coalesceCalls; i++ {
		<-ready
	}
	close(release)
	wg.Wait()

	for _, r := range results {
		if !r.ok() {
			return results, nil
		}
	}

	after, err := g.scrape(ctx)
	if err != nil {
		results[0].err = err

		return results, nil
	}

	sar := map[string]string{"review": "sar"}
	allowed := map[string]string{"decision": "allow"}
	reviews := seriesSum(after, metricReviewCalls, sar) - seriesSum(before, metricReviewCalls, sar)
	decisions := seriesSum(after, metricDecisions, allowed) - seriesSum(before, metricDecisions, allowed)
	misses := seriesSum(after, metricCacheLookups, sarMissLabels()) - seriesSum(before, metricCacheLookups, sarMissLabels())

	// The numbers the verdict is about, so a reader can see what was shared
	// rather than only that something was. An assertion whose evidence is
	// invisible is how the call-counting version of this scenario passed for
	// years without ever proving anything.
	g.logger.Info("coalescing burst",
		slog.String("pod", g.pinned.name), slog.Int("attempt", attempt),
		slog.Int("calls", coalesceCalls), slog.Float64("cache_misses", misses),
		slog.Float64("review_requests", reviews))

	return results, coalescingVerdict(g.pinned.name, coalesceCalls, decisions, misses, reviews)
}

// errNoConcurrentMiss marks a verdict that failed because the burst never
// overlapped in the proxy, which is a timing accident rather than a defect.
var errNoConcurrentMiss = errors.New("the burst produced no concurrent cache misses")

// coalescingVerdict reports whether the deltas one burst produced are evidence
// that the replica shared its SubjectAccessReviews.
//
// Reviews counted against calls is not evidence: one cold live review followed
// by seven ordinary cache hits produces "fewer reviews than calls" without
// anything having overlapped, and firing the calls from goroutines does not
// make the proxy see them at once. The cache misses are what says how many
// calls actually reached the flight group - a hit never gets there - so the
// burst has to produce more than one miss, and those misses have to have been
// answered by fewer reviews than there were of them. Below two misses there is
// nothing to share and the verdict is retryable: the run was mistimed, not
// wrong.
func coalescingVerdict(pod string, calls int, allowed, misses, reviews float64) error {
	switch {
	case int(allowed) != calls:
		return fmt.Errorf("%s allowed %.0f of %d calls, want all of them", pod, allowed, calls)
	case misses < 2:
		return fmt.Errorf("%s answered %d simultaneous calls with %.0f decision-cache miss(es), so at most one reached the flight group: %w",
			pod, calls, misses, errNoConcurrentMiss)
	case reviews < 1:
		return fmt.Errorf("%s recorded %.0f decision-cache misses and no SubjectAccessReview at all; the two counters disagree",
			pod, misses)
	case reviews >= misses:
		return fmt.Errorf("%s issued %.0f SubjectAccessReviews for %.0f concurrent decision-cache misses; they did not coalesce",
			pod, reviews, misses)
	}

	return nil
}
