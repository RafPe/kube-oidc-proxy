// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// AuthenticationAttempt counts one authentication attempt. method is the
// access record's auth_method vocabulary (oidc, tokenreview, none); anything
// else is projected onto other.
func (r *Recorder) AuthenticationAttempt(method string, outcome AuthOutcome) {
	if r == nil {
		return
	}
	r.authnAttempts.WithLabelValues(projectAuthMethod(method), projectAuthOutcome(outcome)).Inc()
}

// AccessDecision counts the one access decision a request produces. An
// allow carries no reason, whatever the caller passed, because the access
// record has none either and the two must agree.
func (r *Recorder) AccessDecision(method string, allowed bool, reason string) {
	if r == nil {
		return
	}
	decision := "deny"
	if allowed {
		decision, reason = "allow", ""
	}
	r.accessDecisions.WithLabelValues(projectAuthMethod(method), decision, projectReason(reason)).Inc()
}
