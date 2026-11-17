// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// AuthenticationAttempt counts one authentication attempt.
func (r *Recorder) AuthenticationAttempt(method AuthMethod, outcome AuthOutcome) {
	if r == nil {
		return
	}
	r.authnAttempts.WithLabelValues(projectAuthMethod(method), projectAuthOutcome(outcome)).Inc()
}

// AccessDecision counts the one access decision a request produces. An
// allow carries no reason, whatever the caller passed, because the access
// record has none either and the two must agree.
func (r *Recorder) AccessDecision(method AuthMethod, allowed bool, reason Reason) {
	if r == nil {
		return
	}
	if allowed {
		reason = ReasonNone
	}
	r.accessDecisions.WithLabelValues(projectAuthMethod(method), string(DecisionFor(allowed)), projectReason(reason)).Inc()
}
