// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// exerciseEverything touches every collector once so each family has a
// series and is present in a Gather.
func exerciseEverything(r *Recorder) {
	r.RequestStarted()
	r.LongRunningEstablished(VerbWatch, ScopeNamespace)
	r.RequestFinished(RequestObservation{Verb: VerbWatch, Scope: ScopeNamespace, Status: 200, Termination: "normal", LongRunning: true, Established: true})
	r.RequestStarted()
	r.RequestFinished(RequestObservation{Verb: VerbGet, Scope: ScopeResource, Status: 200, Termination: "normal", Duration: time.Millisecond})
	r.AuthenticationAttempt("oidc", AuthAccepted)
	r.AccessDecision("oidc", true, "")
	r.ReviewRequest(ReviewSAR, ReviewAllow, time.Millisecond)
	r.CacheLookup(ReviewSAR, CacheMiss)
	r.SetIssuerInitialized("idp.example.com", true)
	r.SetReady(true)
	r.AuditBackendFailure(AuditRun)
}

// TestEveryCollectorIsInTheCatalogue is the contract test: every first-party
// family the registry exports is in the catalogue with the same type, help
// and label names, and every catalogue entry is exported. docs/metrics.md is
// generated from the catalogue, so this is what makes the document true.
func TestEveryCollectorIsInTheCatalogue(t *testing.T) {
	r := newTestRecorder(t)
	exerciseEverything(r)
	families, err := r.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]Spec{}
	for _, s := range Catalogue() {
		byName[s.Name] = s
	}
	seen := map[string]bool{}
	for _, f := range families {
		name := f.GetName()
		if !strings.HasPrefix(name, Namespace+"_") {
			continue // go_*, process_*, promhttp_* are library-owned
		}
		s, ok := byName[name]
		if !ok {
			t.Errorf("%s is exported but not in the catalogue", name)
			continue
		}
		seen[name] = true
		if f.GetHelp() != s.help() {
			t.Errorf("%s help = %q, catalogue says %q", name, f.GetHelp(), s.help())
		}
		wantType := map[string]dto.MetricType{"counter": dto.MetricType_COUNTER, "gauge": dto.MetricType_GAUGE, "histogram": dto.MetricType_HISTOGRAM}[s.Type]
		if f.GetType() != wantType {
			t.Errorf("%s type = %v, catalogue says %s", name, f.GetType(), s.Type)
		}
		// client_golang sorts label pairs by name on the wire; the catalogue
		// keeps constructor order, so compare as sets.
		for _, m := range f.GetMetric() {
			var labels []string
			for _, lp := range m.GetLabel() {
				labels = append(labels, lp.GetName())
			}
			want := slices.Clone(s.Labels)
			slices.Sort(want)
			slices.Sort(labels)
			if !slices.Equal(labels, want) {
				t.Errorf("%s labels = %v, catalogue says %v", name, labels, want)
			}
			break
		}
	}
	for name := range byName {
		if !seen[name] {
			t.Errorf("%s is in the catalogue but exerciseEverything did not export it", name)
		}
	}

	// Lint what the real observation methods export, not only what
	// touchEveryCollector created in Task 5.
	problems, err := testutil.GatherAndLint(r.Gatherer())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("promlint: %s: %s", p.Metric, p.Text)
	}
}

// TestAllowedValuesCoversEveryBoundedLabel pins that the catalogue can answer
// "is this label value one the projections can produce" for every label with
// a closed vocabulary, and says so honestly for the ones without. The e2e
// suite sweeps a live exposition against this, so a value missing here is a
// false failure and a value listed here that no projection emits is a hole.
func TestAllowedValuesCoversEveryBoundedLabel(t *testing.T) {
	// unbounded label names, by family: everything else must be enumerated.
	unbounded := map[string][]string{
		nameBuildInfo:         {"version", "revision", "go_version"},
		nameIssuerInitialized: {"issuer_name"},
	}

	for _, s := range Catalogue() {
		allowed := s.AllowedValues()
		for _, label := range s.Labels {
			values, ok := allowed[label]
			if slices.Contains(unbounded[s.Name], label) {
				if ok {
					t.Errorf("%s: %s is not a closed set but AllowedValues enumerates it", s.Name, label)
				}
				continue
			}
			if !ok {
				t.Errorf("%s: no allowed values for label %s", s.Name, label)
				continue
			}
			if len(values) == 0 {
				t.Errorf("%s: allowed values for %s is empty", s.Name, label)
			}
		}
		for label := range allowed {
			if !slices.Contains(s.Labels, label) {
				t.Errorf("%s: AllowedValues has %s, which is not a label of the family", s.Name, label)
			}
		}
	}
}

// TestAllowedValuesMatchTheProjections is the property that keeps the sets
// honest: every value the catalogue allows is a fixed point of the projection
// that produces it, and the projections' catch-all is allowed too.
func TestAllowedValuesMatchTheProjections(t *testing.T) {
	byName := map[string]Spec{}
	for _, s := range Catalogue() {
		byName[s.Name] = s
	}

	// catchAll is where the projection sends an input outside its set. It is
	// "other" everywhere except scope, whose unknown is the explicit "none".
	cases := []struct {
		family, label string
		project       func(string) string
		catchAll      string
	}{
		{nameRequestsTotal, "k8s_verb", func(v string) string { return projectVerb(Verb(v)) }, other},
		{nameRequestsTotal, "scope", func(v string) string { return projectScope(Scope(v)) }, string(ScopeNone)},
		{nameRequestsTotal, "termination", projectTermination, other},
		{nameAuthnAttempts, "auth_method", projectAuthMethod, other},
		{nameAuthnAttempts, "outcome", func(v string) string { return projectAuthOutcome(AuthOutcome(v)) }, other},
		{nameAccessDecisions, "reason", projectReason, other},
		{nameReviewRequests, "review", func(v string) string { return projectReview(Review(v)) }, other},
		{nameReviewRequests, "outcome", func(v string) string { return projectReviewOutcome(ReviewOutcome(v)) }, other},
		{nameCacheLookups, "cache", func(v string) string { return projectReview(Review(v)) }, other},
		{nameCacheLookups, "result", func(v string) string { return projectCacheResult(CacheResult(v)) }, other},
		{nameAuditBackendFailures, "operation", func(v string) string { return projectAuditOperation(AuditOperation(v)) }, other},
	}

	for _, tc := range cases {
		values := byName[tc.family].AllowedValues()[tc.label]
		if len(values) == 0 {
			t.Errorf("%s/%s: no allowed values", tc.family, tc.label)
			continue
		}
		if got := tc.project("a value no projection knows"); got != tc.catchAll {
			t.Errorf("%s/%s: unknown input projects to %q, want %q", tc.family, tc.label, got, tc.catchAll)
		}
		if !slices.Contains(values, tc.catchAll) {
			t.Errorf("%s/%s: %q is missing; the projection collapses onto it", tc.family, tc.label, tc.catchAll)
		}
		for _, v := range values {
			if got := tc.project(v); got != v {
				t.Errorf("%s/%s: %q projects to %q, so it is not a value the label can carry", tc.family, tc.label, v, got)
			}
		}
	}

	// decision is set in AccessDecision rather than by a projection.
	decisions := byName[nameAccessDecisions].AllowedValues()["decision"]
	slices.Sort(decisions)
	if !slices.Equal(decisions, []string{"allow", "deny"}) {
		t.Errorf("decision = %v, want [allow deny]", decisions)
	}

	// code is the statuses CodeFor renders, plus the two placeholders.
	codes := byName[nameRequestsTotal].AllowedValues()["code"]
	for _, want := range []string{"200", "401", "403", "503", "none", other} {
		if !slices.Contains(codes, want) {
			t.Errorf("code is missing %q", want)
		}
	}
	for _, v := range codes {
		if v == "none" || v == other {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Errorf("code %q is not a status number", v)
			continue
		}
		if got := CodeFor(n); got != v {
			t.Errorf("CodeFor(%d) = %q, want %q", n, got, v)
		}
	}
}
