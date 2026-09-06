// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// SetIssuerInitialized publishes whether the named issuer's authenticator has
// completed initialization. issuerName is the configured issuer's host as
// probe.IssuerName renders it: bounded by the configuration, never a URL.
func (r *Recorder) SetIssuerInitialized(issuerName string, initialized bool) {
	if r == nil {
		return
	}
	r.issuerInitialized.WithLabelValues(issuerName).Set(boolGauge(initialized))
}

// SetReady publishes the readiness latch.
func (r *Recorder) SetReady(ready bool) {
	if r == nil {
		return
	}
	r.ready.Set(boolGauge(ready))
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
