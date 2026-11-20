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

// IssuerToken counts one OIDC token that the issuer issuerName verified, by
// the result of that verification. issuerName is the name of a configured
// issuer, never a value from the token.
func (r *Recorder) IssuerToken(issuerName string, outcome AuthOutcome) {
	if r == nil {
		return
	}
	r.issuerTokens.WithLabelValues(issuerName, projectAuthOutcome(outcome)).Inc()
}

// DeclareIssuer creates the token series of the issuer issuerName at 0, so
// that a dashboard shows the issuer before its first token and rate() does
// not lose the first increase.
func (r *Recorder) DeclareIssuer(issuerName string) {
	if r == nil {
		return
	}
	for _, outcome := range authOutcomes {
		r.issuerTokens.WithLabelValues(issuerName, projectAuthOutcome(outcome))
	}
}
