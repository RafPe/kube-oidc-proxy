// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// Scrape handling limits. MaxRequestsInFlight is the load-bearing one: the
// library default is unlimited, and every concurrent scrape runs a full
// Gather. Timeout bounds the client, not the gathering work.
const (
	maxScrapesInFlight = 3
	scrapeTimeout      = 10 * time.Second
)

// BuildInfo is what the build_info gauge reports. It comes from the ldflags
// the release pipeline sets, never from a request.
type BuildInfo struct {
	Version   string
	Revision  string
	GoVersion string
}

// Recorder owns the private registry and every collector this binary exports.
// It is constructed once in cmd/app and injected into each collaborator; a nil
// *Recorder is a valid, no-op recorder, so a collaborator built without one
// (every existing test does this) needs no special case. A Recorder is safe
// for concurrent use: every method is one atomic update on a client_golang
// collector, and scrapes gather concurrently with them.
//
// Every label value passes through a projection in labels.go before it
// reaches a collector. That is a security control, not tidiness: see the
// comment on `other` there.
type Recorder struct {
	reg *prometheus.Registry

	buildInfo           *prometheus.GaugeVec
	requestsTotal       *prometheus.CounterVec
	requestDuration     *prometheus.HistogramVec
	requestsInFlight    prometheus.Gauge
	longRunningRequests *prometheus.GaugeVec
	authnAttempts       *prometheus.CounterVec
	accessDecisions     *prometheus.CounterVec
	reviewRequests      *prometheus.CounterVec
	reviewDuration      *prometheus.HistogramVec
	cacheLookups        *prometheus.CounterVec
	issuerInitialized   *prometheus.GaugeVec
	ready               prometheus.Gauge
	auditFailures       *prometheus.CounterVec
}

// New builds a Recorder whose registry carries every first-party family plus
// the Go runtime and process collectors. Registration errors are returned,
// never panicked: a metrics misconfiguration is a startup failure like any
// other, reported on the log stream.
func New(build BuildInfo) (*Recorder, error) {
	r := &Recorder{reg: prometheus.NewRegistry()}

	counter := func(name string) *prometheus.CounterVec {
		s := spec(name)
		return prometheus.NewCounterVec(prometheus.CounterOpts{Name: s.Name, Help: s.help()}, s.Labels)
	}
	gaugeVec := func(name string) *prometheus.GaugeVec {
		s := spec(name)
		return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: s.Name, Help: s.help()}, s.Labels)
	}
	gauge := func(name string) prometheus.Gauge {
		s := spec(name)
		return prometheus.NewGauge(prometheus.GaugeOpts{Name: s.Name, Help: s.help()})
	}
	histogram := func(name string, buckets []float64) *prometheus.HistogramVec {
		s := spec(name)
		return prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: s.Name, Help: s.help(), Buckets: buckets}, s.Labels)
	}

	r.buildInfo = gaugeVec(nameBuildInfo)
	r.requestsTotal = counter(nameRequestsTotal)
	r.requestDuration = histogram(nameRequestDuration, requestDurationBuckets)
	r.requestsInFlight = gauge(nameRequestsInFlight)
	r.longRunningRequests = gaugeVec(nameLongRunningRequests)
	r.authnAttempts = counter(nameAuthnAttempts)
	r.accessDecisions = counter(nameAccessDecisions)
	r.reviewRequests = counter(nameReviewRequests)
	r.reviewDuration = histogram(nameReviewDuration, reviewDurationBuckets)
	r.cacheLookups = counter(nameCacheLookups)
	r.issuerInitialized = gaugeVec(nameIssuerInitialized)
	r.ready = gauge(nameReady)
	r.auditFailures = counter(nameAuditBackendFailures)

	for _, c := range []prometheus.Collector{
		r.buildInfo, r.requestsTotal, r.requestDuration, r.requestsInFlight, r.longRunningRequests,
		r.authnAttempts, r.accessDecisions, r.reviewRequests, r.reviewDuration, r.cacheLookups,
		r.issuerInitialized, r.ready, r.auditFailures,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		if err := r.reg.Register(c); err != nil {
			return nil, fmt.Errorf("metrics: registering collector: %w", err)
		}
	}

	r.buildInfo.WithLabelValues(build.Version, build.Revision, build.GoVersion).Set(1)
	return r, nil
}

// Gatherer exposes the registry for tests and the docs generator. Nil for a
// nil recorder.
func (r *Recorder) Gatherer() prometheus.Gatherer {
	if r == nil {
		return nil
	}
	return r.reg
}

// Handler serves the exposition on GET (and HEAD) /metrics. Everything else
// is 404 or 405 with an Allow header: no pprof, no reset, no index page.
// logger receives the gathering errors promhttp would otherwise print to
// stderr. A nil recorder serves 404 for everything.
func (r *Recorder) Handler(logger *slog.Logger) http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	exposition := promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{
		ErrorLog:            scrapeErrorLog{logger: logger},
		ErrorHandling:       promhttp.HTTPErrorOnError,
		Registry:            r.reg,
		MaxRequestsInFlight: maxScrapesInFlight,
		Timeout:             scrapeTimeout,
	})

	// A method pattern is enough: ServeMux answers any method but GET or HEAD
	// on /metrics with 405 and an Allow header, and every other path with 404.
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", exposition)
	return mux
}

// scrapeErrorLog adapts promhttp's Println-style logger onto the log stream.
type scrapeErrorLog struct{ logger *slog.Logger }

func (l scrapeErrorLog) Println(v ...any) {
	logging.Emit(context.Background(), l.logger, logging.EventMetricsScrapeFailed,
		slog.String("error_message", logging.Bound(fmt.Sprint(v...), logging.MaxErrorMessage)))
}
