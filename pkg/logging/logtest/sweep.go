// Copyright Jetstack Ltd. See LICENSE for details.

package logtest

import (
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// AssertRegistered holds every record a capture collected against the event
// registry: a record bridged from a Kubernetes library carries no event_type,
// and every first-party record names a registered event emitted under a
// component and at a level that event's registry entry allows, with all of its
// required attributes present and non-empty.
func AssertRegistered(t testing.TB, c *Capture) {
	t.Helper()
	for _, r := range c.Records() {
		if r.String("component") == string(logging.ComponentK8s) {
			if _, has := r["event_type"]; has {
				t.Errorf("bridged record carries event_type: %v", r)
			}
			continue
		}
		e := logging.EventType(r.String("event_type"))
		spec, ok := e.Spec()
		if !ok {
			t.Errorf("unregistered event_type %q: %v", e, r)
			continue
		}
		if spec.Components != nil && !slices.Contains(spec.Components, logging.Component(r.String("component"))) {
			t.Errorf("%s emitted under component %q", e, r.String("component"))
		}
		if !levelAllowed(spec, r.String("level")) {
			t.Errorf("%s emitted at %s, registry says %s", e, r.String("level"), levelsOf(spec))
		}
		for _, k := range spec.Required {
			if v, has := r[k]; !has || v == "" {
				t.Errorf("%s missing required %s: %v", e, k, r)
			}
		}
	}
}

// levelAllowed reports whether level is one the registry entry permits: the
// declared Level, or one of the alternatives an event whose severity depends on
// the outcome lists in AllowedLevels.
func levelAllowed(spec logging.EventSpec, level string) bool {
	if strings.EqualFold(spec.Level.String(), level) {
		return true
	}
	return slices.ContainsFunc(spec.AllowedLevels, func(l slog.Level) bool {
		return strings.EqualFold(l.String(), level)
	})
}

// levelsOf names the levels a registry entry permits, for a failure message.
func levelsOf(spec logging.EventSpec) string {
	out := []string{spec.Level.String()}
	for _, l := range spec.AllowedLevels {
		out = append(out, l.String())
	}
	return strings.Join(out, " or ")
}
