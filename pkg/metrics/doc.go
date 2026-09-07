// Copyright Jetstack Ltd. See LICENSE for details.

// Package metrics is the home of the proxy's Prometheus registry and of every
// collector it exports. Nothing here is package-level state: the registry and
// the collectors live behind a Recorder that is constructed once and injected,
// exactly as the root *slog.Logger is. The Recorder itself and its injection
// arrive with the metrics endpoint; this phase ships only the package and the
// dependency floor it needs.
package metrics
