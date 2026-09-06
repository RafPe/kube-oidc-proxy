// Copyright Jetstack Ltd. See LICENSE for details.

// Package metrics owns the proxy's Prometheus registry and every collector it
// exports. Nothing here is package-level state: a Recorder is constructed once
// in cmd/app and injected, exactly as the root *slog.Logger is.
package metrics
