// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

var eventGrammar = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2}$`)

var domains = map[string]bool{
	"proxy": true, "request": true, "authn": true, "authz": true, "cache": true,
	"oidc": true, "readiness": true, "upstream": true, "audit": true, "log": true,
}

var actions = map[string]bool{
	"started": true, "completed": true, "failed": true, "stopped": true, "loaded": true,
	"invalid": true, "configured": true, "initialized": true, "pending": true, "ready": true,
	"decided": true, "rewritten": true, "dropped": true, "missing": true, "applied": true,
	"skipped": true, "resolved": true, "succeeded": true, "canceled": true, "suppressed": true,
	"detected": true, "lookup": true,
}

func TestEventTypeGrammar(t *testing.T) {
	seen := map[EventType]bool{}
	for _, e := range AllEventTypes() {
		if !eventGrammar.MatchString(string(e)) {
			t.Errorf("%q does not match <domain>.<object>.<action>", e)
		}
		parts := strings.Split(string(e), ".")
		if !domains[parts[0]] {
			t.Errorf("%q: unknown domain %q", e, parts[0])
		}
		if !actions[parts[2]] {
			t.Errorf("%q: unknown action %q", e, parts[2])
		}
		if seen[e] {
			t.Errorf("%q listed twice", e)
		}
		seen[e] = true
	}
	if got, want := len(AllEventTypes()), 39; got != want {
		t.Errorf("registry has %d events, want %d", got, want)
	}
}

func TestEveryEventIsRegisteredWithValidSpec(t *testing.T) {
	for _, e := range AllEventTypes() {
		spec, ok := e.Spec()
		if !ok {
			t.Errorf("%q has no registry entry", e)
			continue
		}
		if spec.Message == "" {
			t.Errorf("%q has no static message", e)
		}
		switch spec.Level {
		case slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError:
		default:
			t.Errorf("%q has invalid level %v", e, spec.Level)
		}
		for _, c := range spec.Components {
			if c == ComponentK8s {
				t.Errorf("%q is registered for component k8s; bridged records carry no event_type", e)
			}
		}
	}
}

func TestEventAttr(t *testing.T) {
	a := EventRequestAccessDecided.Attr()
	if a.Key != "event_type" || a.Value.String() != "request.access.decided" {
		t.Fatalf("Attr() = %v", a)
	}
}

func TestAllComponentsClosedSet(t *testing.T) {
	if got, want := len(AllComponents()), 11; got != want {
		t.Fatalf("got %d components, want %d", got, want)
	}
}
