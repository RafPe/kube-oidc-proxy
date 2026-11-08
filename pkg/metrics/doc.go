// Copyright Jetstack Ltd. See LICENSE for details.

// Package metrics is the home of the proxy's Prometheus registry and of every
// collector it exports. Nothing here is package-level state: the registry and
// the collectors live behind a Recorder that is constructed once in cmd/app
// and injected, exactly as the root *slog.Logger is. A nil *Recorder is a
// no-op everywhere, so a collaborator built without one cannot panic.
//
// The package also owns the closed request-outcome vocabulary in labels.go --
// AuthMethod, Reason, Termination, Decision, Verb and Scope -- which the
// access record, the error classifier and the request context reuse as their
// own types. One owner is what guarantees that a log record and a metric
// series describing the same request can never disagree.
package metrics
