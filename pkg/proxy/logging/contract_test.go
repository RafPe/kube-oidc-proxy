// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
	"github.com/rafpe/kube-oidc-proxy/pkg/logging/logtest"
	proxycontext "github.com/rafpe/kube-oidc-proxy/pkg/proxy/context"
)

// TestFrozenAccessContract pins the access-log fields issue #129 freezes. The
// fixtures under testdata are the contract as an operator's query sees it: a
// renamed key, a dropped key or a changed value type fails here. Update them
// only when #129's contract itself changes.
func TestFrozenAccessContract(t *testing.T) {
	frozen := []string{"event", "src_ip", "path", "forwarded_for_untrusted", "inbound_user", "inbound_groups",
		"inbound_uid", "inbound_extra", "inbound_extra_omitted", "outbound_user", "outbound_groups", "outbound_uid",
		"outbound_extra", "outbound_extra_omitted"}
	for _, name := range []string{"allow", "deny"} {
		want := map[string]any{}
		raw, err := os.ReadFile(filepath.Join("testdata", "access_decision_"+name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatal(err)
		}
		got := emitFixture(t, name) // builds the same request/users the fixture was generated from
		for _, k := range frozen {
			if _, ok := want[k]; !ok {
				continue
			}
			if !reflect.DeepEqual(got[k], want[k]) {
				t.Errorf("%s: frozen field %s = %v, fixture %v", name, k, got[k], want[k])
			}
		}
		if got["event"] != want["event"] {
			t.Errorf("%s: event = %v", name, got["event"])
		}
	}
}

// TestUpdateFixtures regenerates the golden files. It is skipped by default:
// the contract test above reads the fixture before it emits, so the fixtures
// cannot bootstrap themselves from inside it. Run it deliberately with
// UPDATE_FIXTURES=1 when #129's contract changes, and review the diff.
func TestUpdateFixtures(t *testing.T) {
	if os.Getenv("UPDATE_FIXTURES") != "1" {
		t.Skip("set UPDATE_FIXTURES=1 to regenerate the frozen access-log fixtures")
	}
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allow", "deny"} {
		rec := emitFixture(t, name)

		// time is the one non-deterministic field; it is not part of the
		// frozen contract, so it is stripped rather than committed.
		delete(rec, "time")

		raw, err := json.MarshalIndent(rec, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join("testdata", "access_decision_"+name+".json")
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", path)
	}
}

// emitFixture emits one access record through a real AccessLogger and returns
// it decoded. The allow case is alice impersonating bob, each carrying one
// allowlisted extra and one that must be counted rather than logged; the deny
// case is the impersonation refusal. Both cases are deterministic so the
// golden file is stable.
func emitFixture(t *testing.T, name string) map[string]any {
	t.Helper()

	root, cap := logtest.New(t, 0)
	a := NewAccessLogger(logging.ForComponent(root, logging.ComponentRequest), nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/team-a/pods", nil)
	req.RemoteAddr = "1.2.3.4:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	// Run the header through the real sanitizer so the fixture pins the path
	// production takes: the raw chain is stashed on the context and the header
	// itself is dropped for this untrusted peer.
	req = proxycontext.SanitizeForwardHeaders(req)
	req = proxycontext.WithRequestID(req, "fixture-request-id")

	d := Decision{
		AuthMethod: "oidc",
		Inbound: &user.DefaultInfo{
			Name:   "alice",
			UID:    "alice-uid",
			Groups: []string{"dev"},
			Extra: map[string][]string{
				UserHeaderClientIPKey: {"1.2.3.4"},
				"email":               {"alice@example.com"},
			},
		},
	}

	switch name {
	case "allow":
		d.Allowed = true
		d.Outbound = &user.DefaultInfo{
			Name:   "bob",
			UID:    "bob-uid",
			Groups: []string{"dev"},
			Extra: map[string][]string{
				"originaluser.jetstack.io-user": {"alice"},
				"tenant":                        {"acme"},
			},
		}
	case "deny":
		d.Reason = "impersonation_denied"
		d.TargetKind = "group"
		d.TargetName = "system:masters"
	default:
		t.Fatalf("unknown fixture %q", name)
	}

	a.LogDecision(req, d)

	return cap.Only(t, logging.EventRequestAccessDecided)
}
