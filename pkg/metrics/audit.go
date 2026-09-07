// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// AuditBackendFailure counts an audit backend failure the proxy could
// observe: the backend refusing to start, or reporting on shutdown that it
// dropped events. Asynchronous delivery failures of the bundled backends go
// through the Kubernetes error handler and are not observable here; the
// help string says so.
func (r *Recorder) AuditBackendFailure(op AuditOperation) {
	if r == nil {
		return
	}
	r.auditFailures.WithLabelValues(projectAuditOperation(op)).Inc()
}
