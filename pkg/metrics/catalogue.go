// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// Spec is one entry of the metric catalogue: the name, type, label names and
// their vocabularies, stability and help of a family this binary exports. The
// collectors are built from these entries and docs/metrics.md is generated
// from them, so the two cannot drift.
type Spec struct {
	Name   string
	Type   Type
	Labels []string

	// Values gives, for each label with a closed vocabulary, every value the
	// projections in this package can put on it. A label whose value is
	// bounded in shape but not enumerable -- issuer_name is a host, the
	// build_info labels are build strings -- has no entry. The vocabulary is
	// the family's, not the label name's: outcome means one thing on the
	// authentication counter and another on the review counters. Read it
	// through AllowedValues.
	Values map[string]func() []string

	Stability Stability
	Help      string // without the stability prefix; help() adds it
}

// Type is the Prometheus type of a catalogue family. Its constants are the
// closed set the collectors are built as; the value is what docs/metrics.md
// prints.
type Type string

const (
	TypeCounter   Type = "counter"
	TypeGauge     Type = "gauge"
	TypeHistogram Type = "histogram"
)

// Stability is a family's stability level, the marker kube-apiserver's
// metrics put in front of their help. STABLE families keep their name, type
// and labels; ALPHA ones may still change.
type Stability string

const (
	StabilityStable Stability = "STABLE"
	StabilityAlpha  Stability = "ALPHA"
)

// help renders the help string as exported, with the stability marker in
// front, the convention kube-apiserver's metrics use.
func (s Spec) help() string {
	return "[" + string(s.Stability) + "] " + s.Help
}

// Names of every first-party family, so a collector and the docs share one
// constant.
const (
	nameBuildInfo            = Namespace + "_build_info"
	nameRequestsTotal        = Namespace + "_requests_total"
	nameRequestDuration      = Namespace + "_request_duration_seconds"
	nameRequestsInFlight     = Namespace + "_requests_in_flight"
	nameLongRunningRequests  = Namespace + "_long_running_requests"
	nameAuthnAttempts        = Namespace + "_authentication_attempts_total"
	nameAccessDecisions      = Namespace + "_access_decisions_total"
	nameReviewRequests       = Namespace + "_review_requests_total"
	nameReviewDuration       = Namespace + "_review_request_duration_seconds"
	nameCacheLookups         = Namespace + "_cache_lookups_total"
	nameIssuerInitialized    = Namespace + "_oidc_issuer_initialized"
	nameReady                = Namespace + "_ready"
	nameAuditBackendFailures = Namespace + "_audit_backend_failures_total"
)

// Catalogue lists every first-party family, as a fresh literal on every call
// so nothing package-level is mutable and the caller owns the slice. Order is
// the order docs/metrics.md renders them in. Append-only: a shipped name,
// label set or type is never changed in place.
func Catalogue() []Spec {
	verbScope := map[string]func() []string{"k8s_verb": closed(verbs), "scope": closed(scopes)}
	review := map[string]func() []string{"review": closed(reviews, other), "outcome": closed(reviewOutcomes, other)}

	return []Spec{
		{Name: nameBuildInfo, Type: TypeGauge, Labels: []string{"version", "revision", "go_version"}, Stability: StabilityStable,
			Help: "Build information; always 1."},
		{Name: nameRequestsTotal, Type: TypeCounter, Labels: []string{"k8s_verb", "scope", "code", "termination"}, Stability: StabilityStable,
			Values: map[string]func() []string{
				"k8s_verb": closed(verbs), "scope": closed(scopes), "code": allowedCodes, "termination": closed(terminations, other),
			},
			Help: "Completed requests by Kubernetes verb, scope, HTTP status code and how the exchange ended."},
		{Name: nameRequestDuration, Type: TypeHistogram, Labels: []string{"k8s_verb", "scope"}, Stability: StabilityStable,
			Values: verbScope,
			Help:   "Latency of completed requests in seconds, excluding long-running (watch, exec, attach, portforward, logs, proxy) and hijacked requests."},
		{Name: nameRequestsInFlight, Type: TypeGauge, Labels: nil, Stability: StabilityStable,
			Help: "Requests currently inside the handler chain."},
		{Name: nameLongRunningRequests, Type: TypeGauge, Labels: []string{"k8s_verb", "scope"}, Stability: StabilityStable,
			Values: verbScope,
			Help:   "Long-running requests whose response has started (headers written or connection hijacked) and not yet ended."},
		{Name: nameAuthnAttempts, Type: TypeCounter, Labels: []string{"auth_method", "outcome"}, Stability: StabilityStable,
			Values: map[string]func() []string{"auth_method": closed(authMethods, other), "outcome": closed(authOutcomes, other)},
			Help:   "Authentication attempts by method and outcome, before the identity and authorization checks that follow."},
		{Name: nameAccessDecisions, Type: TypeCounter, Labels: []string{"auth_method", "decision", "reason"}, Stability: StabilityStable,
			Values: map[string]func() []string{
				"auth_method": closed(authMethods, other), "decision": closed([]Decision{DecisionAllow, DecisionDeny}), "reason": closed(reasons, other),
			},
			Help: "Final access decisions; reason is empty on allow."},
		{Name: nameReviewRequests, Type: TypeCounter, Labels: []string{"review", "outcome"}, Stability: StabilityStable,
			Values: review,
			Help:   "TokenReview and SubjectAccessReview API calls actually issued to the API server, by outcome."},
		{Name: nameReviewDuration, Type: TypeHistogram, Labels: []string{"review", "outcome"}, Stability: StabilityStable,
			Values: review,
			Help:   "Latency of review API calls in seconds."},
		{Name: nameCacheLookups, Type: TypeCounter, Labels: []string{"cache", "result"}, Stability: StabilityStable,
			Values: map[string]func() []string{"cache": closed(reviews, other), "result": closed(cacheResults, other)},
			Help:   "Review cache lookups by cache and result."},
		{Name: nameIssuerInitialized, Type: TypeGauge, Labels: []string{"issuer_name"}, Stability: StabilityStable,
			Help: "1 once the issuer's authenticator has fetched its JWKS. Reports initialization, not ongoing issuer availability."},
		{Name: nameReady, Type: TypeGauge, Labels: nil, Stability: StabilityStable,
			Help: "1 once the proxy is serving and readiness has latched."},
		{Name: nameAuditBackendFailures, Type: TypeCounter, Labels: []string{"operation"}, Stability: StabilityAlpha,
			Values: map[string]func() []string{"operation": closed(auditOperations, other)},
			Help:   "Audit backend failures observable at start. Asynchronous delivery failures and lost flushes at shutdown are not included."},
	}
}

// spec returns the catalogue entry for name. A missing entry is a programming
// error caught by TestEveryCollectorIsInTheCatalogue, so it panics.
func spec(name string) Spec {
	for _, s := range Catalogue() {
		if s.Name == name {
			return s
		}
	}
	panic("metrics: " + name + " is not in the catalogue")
}

// Bucket boundaries. The request histogram reuses kube-apiserver's STABLE
// apiserver_request_duration_seconds buckets verbatim, so the proxy's and the
// API server's quantiles interpolate identically and can sit on one panel.
// The review histogram uses the shorter list kube-apiserver applies to its
// own filter latency: a review is a single API round trip.
var (
	requestDurationBuckets = []float64{0.005, 0.025, 0.05, 0.1, 0.2, 0.4, 0.6, 0.8, 1.0, 1.25, 1.5, 2, 3, 4, 5, 6, 8, 10, 15, 20, 30, 45, 60}
	reviewDurationBuckets  = []float64{0.0001, 0.0003, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1, 5, 10, 15, 30}
)

// AllowedValues returns, for each of this family's labels that has a closed
// vocabulary, every value the projections in this package can put on it (see
// Values). A label without one is absent from the map, which is how a caller
// tells "unbounded" from "empty set". Each call builds a fresh map and fresh
// slices the caller owns.
func (s Spec) AllowedValues() map[string][]string {
	out := map[string][]string{}
	for _, label := range s.Labels {
		if values, ok := s.Values[label]; ok {
			out[label] = values()
		}
	}
	return out
}

// closed returns the vocabulary of a label whose values are a typed set,
// rendered as plain strings, plus any catch-all the projection collapses an
// undocumented input onto. The set is rendered on each call, so the caller
// owns the slice.
func closed[T ~string](values []T, catchAll ...string) func() []string {
	return func() []string {
		out := make([]string, 0, len(values)+len(catchAll))
		for _, v := range values {
			out = append(out, string(v))
		}
		return append(out, catchAll...)
	}
}

// allowedCodes is every value CodeFor can render: the statuses Go's registry
// knows, plus codeNone for a request that ended without one and the catch-all.
// Derived from CodeFor rather than listed, so the two cannot drift.
func allowedCodes() []string {
	out := []string{codeNone, other}
	for status := 100; status < 600; status++ {
		if code := CodeFor(status); code != other {
			out = append(out, code)
		}
	}
	return out
}
