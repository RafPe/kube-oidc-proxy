// Copyright Jetstack Ltd. See LICENSE for details.
package metrics

// AuditBackendFailure counts an audit backend failure the proxy could
// observe: the backend refusing to start. Asynchronous delivery failures and
// a flush that loses events at shutdown go through the Kubernetes error
// handler -- the upstream backends' Shutdown returns nothing -- and are not
// observable here; the help string says so.
func (r *Recorder) AuditBackendFailure(op AuditOperation) {
	if r == nil {
		return
	}
	r.auditFailures.WithLabelValues(projectAuditOperation(op)).Inc()
}
