// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

import (
	"testing"

	"github.com/rafpe/kube-oidc-proxy/pkg/metrics/metricstest"
)

func TestAuthenticationAttemptAndAccessDecision(t *testing.T) {
	r := newTestRecorder(t)
	r.AuthenticationAttempt("oidc", AuthRejected)
	r.AuthenticationAttempt("tokenreview", AuthAccepted)
	r.AccessDecision("tokenreview", true, "")
	r.AccessDecision("none", false, "unauthorized")
	r.AccessDecision("oidc", true, "should-be-dropped")
	r.AccessDecision("weird", false, "made-up")

	g := r.Gatherer()
	if v, _ := metricstest.Value(t, g, nameAuthnAttempts, map[string]string{"auth_method": "oidc", "outcome": "rejected"}); v != 1 {
		t.Fatalf("attempts{oidc,rejected} = %v", v)
	}
	if v, _ := metricstest.Value(t, g, nameAccessDecisions, map[string]string{"auth_method": "tokenreview", "decision": "allow", "reason": ""}); v != 1 {
		t.Fatalf("decisions{tokenreview,allow} = %v", v)
	}
	if v, _ := metricstest.Value(t, g, nameAccessDecisions, map[string]string{"auth_method": "none", "decision": "deny", "reason": "unauthorized"}); v != 1 {
		t.Fatalf("decisions{none,deny,unauthorized} = %v", v)
	}
	// An allow never carries a reason, whatever the caller passed.
	if v, _ := metricstest.Value(t, g, nameAccessDecisions, map[string]string{"auth_method": "oidc", "decision": "allow", "reason": ""}); v != 1 {
		t.Fatalf("allow with a reason was not normalised: %v", v)
	}
	if v, _ := metricstest.Value(t, g, nameAccessDecisions, map[string]string{"auth_method": "other", "decision": "deny", "reason": "other"}); v != 1 {
		t.Fatalf("unknown method/reason not projected onto other: %v", v)
	}
	var nilr *Recorder
	nilr.AuthenticationAttempt("oidc", AuthAccepted)
	nilr.AccessDecision("oidc", true, "")
}

func TestDeclareIssuerCreatesEachOutcomeAtZero(t *testing.T) {
	r := newTestRecorder(t)
	r.DeclareIssuer("platform")
	r.IssuerToken("platform", AuthRejected)
	for outcome, want := range map[string]float64{"accepted": 0, "rejected": 1, "error": 0} {
		v, ok := metricstest.Value(t, r.Gatherer(), nameIssuerTokens, map[string]string{"issuer_name": "platform", "outcome": outcome})
		if !ok || v != want {
			t.Errorf("issuer_tokens{platform,%s} = %v (present %v), want %v", outcome, v, ok, want)
		}
	}
}

func TestNilRecorderIssuerTokenIsNoOp(t *testing.T) {
	var r *Recorder
	r.IssuerToken("platform", AuthAccepted)
	r.DeclareIssuer("platform")
}
