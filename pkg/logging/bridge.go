// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"context"
	"flag"
	"log/slog"
	"strconv"

	"k8s.io/klog/v2"
)

// bridgeHandler wraps the root logger's handler for records that arrive from
// klog and the Kubernetes libraries behind it. Those records are not
// first-party events: they carry component=k8s and never an event_type, and
// their klog V(n) levels are folded onto DEBUG so the single -v knob keeps
// deciding what is shown.
type bridgeHandler struct {
	inner     slog.Handler
	verbosity int
}

// Enabled applies the -v verbosity to klog's V(n) levels, which logr renders
// as negative slog levels. INFO and above are left to the root handler, so
// WARN and ERROR from Kubernetes libraries are never hidden.
func (b bridgeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	if l < slog.LevelInfo { // klog V(n) arrives as -n
		return int(-l) <= b.verbosity
	}
	return b.inner.Enabled(ctx, l)
}

// Handle folds every V(n) level onto DEBUG and tags the record as bridged.
// The rewrite happens before delegating, so a -v>=1 root accepts the record;
// a -v=0 root never sees one, because Enabled already refused it.
func (b bridgeHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < slog.LevelInfo {
		r.Level = slog.LevelDebug
	}
	r.AddAttrs(slog.String("component", string(ComponentK8s)))
	return b.inner.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (b bridgeHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return bridgeHandler{b.inner.WithAttrs(a), b.verbosity}
}

// WithGroup implements slog.Handler.
func (b bridgeHandler) WithGroup(g string) slog.Handler {
	return bridgeHandler{b.inner.WithGroup(g), b.verbosity}
}

// InstallKlogBridge routes every record the Kubernetes libraries emit through
// klog into the root logger, so the process has one log stream in one format.
// Call it once, right after the root logger is built.
//
// It also sets klog's own -v to the verbosity it is given. klog decides V(n)
// against that global before it ever consults the installed logger, so without
// this every V(n) record would be dropped ahead of bridgeHandler.Enabled. In
// production the value already arrives at klog from the same -v flag via
// globalflag, so the write is idempotent; making it here means the bridge is
// the single place where klog's verbosity is reconciled with the slog floor.
func InstallKlogBridge(root *slog.Logger, verbosity int) {
	// InitFlags only re-registers klog's existing flag.Value objects, so
	// nothing else klog holds (vmodule, logtostderr, ...) is disturbed.
	var fs flag.FlagSet
	klog.InitFlags(&fs)
	_ = fs.Set("v", strconv.Itoa(verbosity))

	klog.SetSlogLogger(slog.New(bridgeHandler{inner: root.Handler(), verbosity: verbosity}))
}
