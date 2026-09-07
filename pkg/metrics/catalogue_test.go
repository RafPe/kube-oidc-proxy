// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"slices"
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
