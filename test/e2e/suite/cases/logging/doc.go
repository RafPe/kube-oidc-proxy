// Copyright Jetstack Ltd. See LICENSE for details.

// Package logging asserts the proxy's structured log stream end to end: that
// every line it writes is one JSON record carrying the schema version and its
// component, that startup and readiness are recorded, that a request can be
// followed from the Audit-ID the client is handed through to the terminal
// record, that a client cannot choose its own correlation id, that credentials
// never reach the stream, and that records bridged from the Kubernetes
// libraries arrive as component=k8s.
//
// The specs read the proxy's own container logs, which is the only place the
// stream is observable exactly as an operator's collector would see it: unit
// tests can only assert what a handler was given, not what the process
// actually wrote at the verbosity the suite deploys.
package logging
