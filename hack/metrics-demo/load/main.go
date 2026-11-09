// Copyright Jetstack Ltd. See LICENSE for details.

// Command load drives every kind of traffic the metric catalogue can observe
// through the demo proxy, so that every dashboard panel has something to draw.
// One scenario per metric family or label value: allowed and forbidden
// requests, invalid and expired tokens, allowed and denied impersonation, the
// two anomaly denials, both token-passthrough outcomes, a watch, an exec, a
// log stream, non-resource paths and requests with verbs that are not
// Kubernetes verbs at all.
//
// With --once each scenario runs exactly once and the program exits non-zero
// if any call did not produce its expected status; that is this task's test.
// With --duration it rotates through them until the time is up.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	// The identity the demo's OIDC tokens carry, and the one the demo RBAC
	// grants; see hack/metrics-demo/demo-identities.yaml.
	demoUser        = "user@example.com"
	demoClientID    = "kube-oidc-proxy"
	demoPod         = "demo-shell"
	demoSA          = "demo-passthrough"
	impersonated    = "jjackson"
	notImpersonated = "mallory"

	// cacheWarmCalls is how many identical calls a cache-exercising scenario
	// makes. The proxy runs two replicas behind a ClusterIP, each with its own
	// cache, so three identical calls guarantee at least one lands on a
	// replica that has already cached the decision.
	cacheWarmCalls = 3

	// coalesceCalls is how many identical impersonation calls the coalescing
	// scenario releases at one replica together. More than a handful and the
	// scenario stops being about coalescing and starts being about the
	// client's own concurrency; fewer and one mistimed call would leave too
	// few concurrent cache misses for the verdict to read.
	coalesceCalls = 8

	// coalesceAttempts is how many times the burst is retried when it did not
	// overlap inside the proxy. Overlap is the one thing the client cannot
	// make certain, and each attempt costs another sarCacheTTL, so the retry
	// is bounded and a persistent failure to overlap is still a failure.
	coalesceAttempts = 3

	// sarCacheTTL is pkg/authz/subjectaccessreview.DefaultAllowCacheTTL, which
	// the chart does not override in the demo. The coalescing scenario waits
	// this out so the replica it addresses answers from a genuinely cold
	// cache; without the wait it would measure the cache, not the flight
	// group. Not imported, so this program stays a client of the deployed
	// proxy rather than of the package it was built from.
	sarCacheTTL = 10 * time.Second

	// The proxy Service and the container ports the chart renders
	// (chart/kube-oidc-proxy/templates/deployment.yaml). The metrics port is
	// the only named one, so it is looked up by name and never assumed.
	proxyService       = "svc/kop-kube-oidc-proxy"
	proxyServicePort   = 443
	proxyPodPort       = 8443
	metricsPortName    = "metrics"
	proxyPodSelector   = "app.kubernetes.io/name=kube-oidc-proxy,app.kubernetes.io/instance=kop"
	metricDecisions    = "kube_oidc_proxy_access_decisions_total"
	metricReviewCalls  = "kube_oidc_proxy_review_requests_total"
	metricCacheLookups = "kube_oidc_proxy_cache_lookups_total"

	// statusNone marks a scenario that completes without an HTTP status the
	// client can observe, because the connection was upgraded or streamed.
	statusNone = 0

	// hostileMethodCount is how many non-Kubernetes methods the hostile
	// scenario sends, and hostileMethodStatus what each must answer with:
	// observed against the demo cluster, not assumed. The proxy authenticates
	// the token and impersonates, and the API server then refuses a verb its
	// RBAC has no rule for.
	hostileMethodCount  = 9
	hostileMethodStatus = http.StatusForbidden

	// noUsernameClaimStatus is what the proxy answers a token that carries no
	// username: the identity authenticated but names nobody, so there is
	// nobody to impersonate. Not 401 - the token itself was accepted.
	noUsernameClaimStatus = http.StatusForbidden

	// How many times the tunnel tries to come back after kubectl drops it.
	tunnelReopenAttempts = 10

	// portForwardReadyTimeout bounds how long a freshly started kubectl may
	// take to announce its local port. The announcement is the only readiness
	// signal there is, and reading for it has no natural end: a kubectl that
	// never announces one - the pod gone, the upgrade refused - would
	// otherwise block its caller for ever, and Close behind it.
	portForwardReadyTimeout = 30 * time.Second

	watchHold   = 20 * time.Second
	callTimeout = 30 * time.Second
)

// options are the command-line flags.
type options struct {
	state     string
	namespace string
	duration  time.Duration
	interval  time.Duration
	once      bool
}

func main() {
	var opts options
	flag.StringVar(&opts.state, "state", "hack/metrics-demo/.state", "directory up.sh wrote the demo's kubeconfig and key material to")
	flag.StringVar(&opts.namespace, "namespace", "proxy", "namespace the proxy and the demo workload run in")
	flag.DurationVar(&opts.duration, "duration", 10*time.Minute, "how long to keep generating traffic")
	flag.DurationVar(&opts.interval, "interval", 500*time.Millisecond, "pause between calls")
	flag.BoolVar(&opts.once, "once", false, "run each scenario exactly once and assert its expected status")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger, opts); err != nil {
		logger.Error("load generator failed", slog.String("error_message", err.Error()))
		os.Exit(1)
	}
}

func run(logger *slog.Logger, opts options) error {
	// Ctrl-C on a foreground run, or a SIGTERM, cancels this context instead
	// of killing the process where it stands. Everything below hangs off it -
	// the calls in flight, the timed loop, and the port-forwards, which close
	// themselves on cancellation - so an interrupted run leaves no kubectl
	// children behind.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := loadState(opts.state)
	if err != nil {
		return err
	}

	tun, err := newTunnel(ctx, st.kubeconfig, opts.namespace, proxyService, proxyServicePort, "https", logger)
	if err != nil {
		return err
	}
	defer tun.Close()

	g, err := newGenerator(logger, st, opts.namespace, tun)
	if err != nil {
		return err
	}

	// The scenarios that assert on how far a counter moved need one replica
	// they can address directly, and that replica's own /metrics.
	pin, err := g.pin(ctx, logger)
	if err != nil {
		return err
	}
	defer pin.Close()
	g.pinned = pin

	scenarios := g.scenarios()

	if opts.once {
		return g.runOnce(ctx, logger, scenarios)
	}

	return g.runFor(ctx, logger, scenarios, opts.duration, opts.interval)
}

// runOnce runs every scenario once and fails if any of its calls produced an
// unexpected status. This is the test for the load generator itself.
func (g *generator) runOnce(ctx context.Context, logger *slog.Logger, scenarios []scenario) error {
	var failures []string
	calls := 0

	for _, s := range scenarios {
		for _, r := range g.call(ctx, logger, s) {
			calls++
			switch {
			case r.err != nil:
				failures = append(failures, fmt.Sprintf("%s: %s", r.kind, r.err))
			case r.status != r.want:
				failures = append(failures, fmt.Sprintf("%s: status %d, want %d", r.kind, r.status, r.want))
			}
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("%d of %d calls across %d scenarios did not behave as expected:\n  %s",
			len(failures), calls, len(scenarios), strings.Join(failures, "\n  "))
	}

	logger.Info("every call produced its expected status",
		slog.Int("scenarios", len(scenarios)), slog.Int("calls", calls))

	return nil
}

// runFor rotates through the scenarios until the duration is up, so every
// family keeps receiving traffic while the dashboards are watched.
func (g *generator) runFor(ctx context.Context, logger *slog.Logger, scenarios []scenario, duration, interval time.Duration) error {
	deadline := time.Now().Add(duration)
	for i := 0; time.Now().Before(deadline); i++ {
		s := scenarios[i%len(scenarios)]
		for _, r := range g.call(ctx, logger, s) {
			if r.err != nil {
				// A failure mid-run is traffic too: log it and keep going, so
				// a transient API server hiccup does not end a ten-minute run.
				logger.Warn("call failed", slog.String("kind", r.kind),
					slog.String("error_message", r.err.Error()))
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}

	logger.Info("load finished", slog.String("duration", duration.String()))

	return nil
}

// call runs one scenario and logs one record per call it made, so a reader can
// line the log up against the counters call by call rather than scenario by
// scenario.
func (g *generator) call(ctx context.Context, logger *slog.Logger, s scenario) []result {
	results := s.run(ctx)
	for _, r := range results {
		attrs := []any{
			slog.String("kind", r.kind),
			slog.Int("status", r.status),
			slog.Int64("duration_ms", r.duration.Milliseconds()),
			slog.Bool("ok", r.ok()),
		}
		if r.err != nil {
			attrs = append(attrs, slog.String("error_message", r.err.Error()))
		}
		logger.Info("call", attrs...)
	}

	return results
}
