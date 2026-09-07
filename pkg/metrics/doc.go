// Copyright Jetstack Ltd. See LICENSE for details.

// Package metrics is the home of the proxy's Prometheus registry and of every
// collector it exports. Nothing here is package-level state: the registry and
// the collectors live behind a Recorder that is constructed once in cmd/app
// and injected, exactly as the root *slog.Logger is. A nil *Recorder is a
// no-op everywhere, so a collaborator built without one cannot panic.
package metrics
