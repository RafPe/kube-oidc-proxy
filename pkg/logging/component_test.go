// Copyright Jetstack Ltd. See LICENSE for details.
package logging_test

import (
	"slices"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
)

// TestAllComponentsIsClosedAndDistinct pins the component set every record
// draws from: each value appears once, and the bridge's k8s component is
// among them.
func TestAllComponentsIsClosedAndDistinct(t *testing.T) {
	all := logging.AllComponents()
	seen := map[logging.Component]bool{}
	for _, c := range all {
		if c == "" {
			t.Error("empty component in AllComponents")
		}
		if seen[c] {
			t.Errorf("component %q listed twice", c)
		}
		seen[c] = true
	}
	for _, want := range []logging.Component{logging.ComponentStartup, logging.ComponentRequest, logging.ComponentK8s, logging.ComponentMetrics} {
		if !slices.Contains(all, want) {
			t.Errorf("AllComponents() lacks %q", want)
		}
	}
}

// TestForComponentStampsTheComponentAttribute pins that a component logger
// carries exactly the component attribute Emit relies on.
func TestForComponentStampsTheComponentAttribute(t *testing.T) {
	root, cap := logtest.New(t, 0)
	logging.ForComponent(root, logging.ComponentSAR).Info("hello")
	recs := cap.Records()
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if got := recs[0].String("component"); got != string(logging.ComponentSAR) {
		t.Fatalf("component = %q, want %q", got, logging.ComponentSAR)
	}
}
