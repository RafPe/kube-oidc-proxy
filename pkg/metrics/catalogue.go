// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// Spec is one entry of the metric catalogue: the name, type, label names,
// stability and help of a family this binary exports. The collectors are
// built from these entries and docs/metrics.md is generated from them, so
// the two cannot drift.
type Spec struct {
	Name      string
	Type      string // counter, gauge or histogram
	Labels    []string
	Stability string // STABLE or ALPHA
	Help      string // without the stability prefix; help() adds it
}

// help renders the help string as exported, with the stability marker in
// front, the convention kube-apiserver's metrics use.
func (s Spec) help() string {
	return "[" + s.Stability + "] " + s.Help
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

// catalogue lists every first-party family, as a fresh literal on every call
// so nothing package-level is mutable. Order is the order docs/metrics.md
// renders them in. Append-only: a shipped name, label set or type is never
// changed in place.
func catalogue() []Spec {
	return []Spec{
		{Name: nameBuildInfo, Type: "gauge", Labels: []string{"version", "revision", "go_version"}, Stability: "STABLE",
			Help: "Build information; always 1."},
		{Name: nameRequestsTotal, Type: "counter", Labels: []string{"k8s_verb", "scope", "code", "termination"}, Stability: "STABLE",
			Help: "Completed requests by Kubernetes verb, scope, HTTP status code and how the exchange ended."},
		{Name: nameRequestDuration, Type: "histogram", Labels: []string{"k8s_verb", "scope"}, Stability: "STABLE",
			Help: "Latency of completed requests in seconds, excluding long-running (watch, exec, attach, portforward, logs, proxy) and hijacked requests."},
		{Name: nameRequestsInFlight, Type: "gauge", Labels: nil, Stability: "STABLE",
			Help: "Requests currently inside the handler chain."},
		{Name: nameLongRunningRequests, Type: "gauge", Labels: []string{"k8s_verb", "scope"}, Stability: "STABLE",
			Help: "Long-running requests whose response has started (headers written or connection hijacked) and not yet ended."},
		{Name: nameAuthnAttempts, Type: "counter", Labels: []string{"auth_method", "outcome"}, Stability: "STABLE",
			Help: "Authentication attempts by method and outcome, before the identity and authorization checks that follow."},
		{Name: nameAccessDecisions, Type: "counter", Labels: []string{"auth_method", "decision", "reason"}, Stability: "STABLE",
			Help: "Final access decisions; reason is empty on allow."},
		{Name: nameReviewRequests, Type: "counter", Labels: []string{"review", "outcome"}, Stability: "STABLE",
			Help: "TokenReview and SubjectAccessReview API calls actually issued to the API server, by outcome."},
		{Name: nameReviewDuration, Type: "histogram", Labels: []string{"review", "outcome"}, Stability: "STABLE",
			Help: "Latency of review API calls in seconds."},
		{Name: nameCacheLookups, Type: "counter", Labels: []string{"cache", "result"}, Stability: "STABLE",
			Help: "Review cache lookups by cache and result."},
		{Name: nameIssuerInitialized, Type: "gauge", Labels: []string{"issuer_name"}, Stability: "STABLE",
			Help: "1 once the issuer's authenticator has fetched its JWKS. Reports initialization, not ongoing issuer availability."},
		{Name: nameReady, Type: "gauge", Labels: nil, Stability: "STABLE",
			Help: "1 once the proxy is serving and readiness has latched."},
		{Name: nameAuditBackendFailures, Type: "counter", Labels: []string{"operation"}, Stability: "ALPHA",
			Help: "Audit backend failures observable at start and shutdown. Asynchronous delivery failures are not included."},
	}
}

// Catalogue returns every first-party family, in documentation order. Each
// call returns a fresh slice the caller owns.
func Catalogue() []Spec {
	return catalogue()
}

// spec returns the catalogue entry for name. A missing entry is a programming
// error caught by TestEveryCollectorIsInTheCatalogue, so it panics.
func spec(name string) Spec {
	for _, s := range catalogue() {
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
// vocabulary, every value the projections in this package can put on it. A
// label whose value is bounded in shape but not enumerable -- issuer_name is
// a host, the build_info labels are build strings -- is absent from the map,
// which is how a caller tells "unbounded" from "empty set".
//
// The vocabulary is per family, not per label name: outcome means one thing
// on the authentication counter and another on the review counters.
//
// Each call builds a fresh map and fresh slices the caller owns; nothing here
// is package-level state.
func (s Spec) AllowedValues() map[string][]string {
	out := map[string][]string{}
	for _, label := range s.Labels {
		if values := allowedValuesFor(s.Name, label); values != nil {
			out[label] = values
		}
	}
	return out
}

// allowedValuesFor is the closed vocabulary of one label on one family, or
// nil when the label has none. Written as a switch rather than a table so it
// stays a constant a reader and a linter can both see through, and kept
// beside the catalogue so a new family cannot be added without deciding what
// its labels may carry.
func allowedValuesFor(family, label string) []string {
	switch family {
	case nameBuildInfo:
		return nil // version, revision and go_version are build strings
	case nameIssuerInitialized:
		return nil // issuer_name is a host, checked by shape
	}

	switch label {
	case "k8s_verb":
		return []string{
			string(VerbGet), string(VerbList), string(VerbWatch), string(VerbCreate),
			string(VerbUpdate), string(VerbPatch), string(VerbDelete),
			string(VerbDeleteCollection), string(VerbProxy), string(VerbConnect),
			string(VerbOther),
		}
	case "scope":
		return []string{string(ScopeCluster), string(ScopeNamespace), string(ScopeResource), string(ScopeNone)}
	case "code":
		return allowedCodes()
	case "termination":
		return []string{
			"normal", "hijacked", "client_cancel", "panic",
			"upstream_timeout", "upstream_reset", "proxy_error", other,
		}
	case "auth_method":
		return []string{"oidc", "tokenreview", "none", other}
	case "decision":
		return []string{"allow", "deny"}
	case "reason":
		return []string{
			"", "unauthorized", "reserved_identity", "no_username_claim",
			"impersonation_denied", "too_many_impersonation_values", "client_canceled",
			"internal_error", "upstream_error", "authentication_dependency_error", other,
		}
	case "review", "cache":
		return []string{string(ReviewTokenReview), string(ReviewSAR), other}
	case "result":
		return []string{string(CacheHit), string(CacheMiss), string(CacheBypass), other}
	case "operation":
		return []string{string(AuditRun), string(AuditShutdown), other}
	case "outcome":
		if family == nameAuthnAttempts {
			return []string{string(AuthAccepted), string(AuthRejected), string(AuthError), other}
		}
		return []string{
			string(ReviewAllow), string(ReviewDeny), string(ReviewTimeout),
			string(ReviewCanceled), string(ReviewError), other,
		}
	}
	return nil
}

// allowedCodes is every value CodeFor can render: the statuses Go's registry
// knows, plus "none" for a request that ended without one and the catch-all.
// Derived from CodeFor rather than listed, so the two cannot drift.
func allowedCodes() []string {
	out := []string{"none", other}
	for status := 100; status < 600; status++ {
		if code := CodeFor(status); code != other {
			out = append(out, code)
		}
	}
	return out
}
