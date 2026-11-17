// Copyright Jetstack Ltd. See LICENSE for details.
package logging

import (
	"context"
	"flag"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	"k8s.io/klog/v2"
)

// bridgeHandler wraps the root logger's handler for records that arrive from
// klog and the Kubernetes libraries behind it. Those records are not
// first-party events: they carry component=k8s and never an event_type, and
// their klog V(n) levels are folded onto DEBUG so the single -v knob keeps
// deciding what is shown.
//
// inner already carries component=k8s, bound before any group a derived
// logger opens, so the tag stays a top-level field on every bridged record.
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

// Handle folds every V(n) level onto DEBUG. The rewrite happens before
// delegating, so a -v>=1 root accepts the record; a -v=0 root never sees one,
// because Enabled already refused it.
func (b bridgeHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level < slog.LevelInfo {
		r.Level = slog.LevelDebug
	}
	return b.inner.Handle(ctx, r)
}

// WithAttrs implements slog.Handler. The derived handler is still a bridge, so
// a logger the Kubernetes libraries derive with WithValues keeps the -v gate.
func (b bridgeHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return bridgeHandler{b.inner.WithAttrs(a), b.verbosity}
}

// WithGroup implements slog.Handler, keeping the bridge as WithAttrs does.
func (b bridgeHandler) WithGroup(g string) slog.Handler {
	return bridgeHandler{b.inner.WithGroup(g), b.verbosity}
}

// klogBridge is the handler klog holds. klog keeps its logger in a
// process-global that it reads without synchronization, so the bridge is handed
// to klog exactly once and never replaced: a goroutine a Kubernetes library left
// running (a certificate reloader logging as it stops, say) may read it at any
// time. Each InstallKlogBridge swaps only the target behind it, atomically.
//
// A logger a library derives with WithValues or WithGroup records those steps
// in ops and replays them on whatever target is current when a record arrives.
type klogBridge struct {
	ops []func(slog.Handler) slog.Handler
}

// klogTarget is the bridgeHandler records are currently routed to.
var klogTarget atomic.Pointer[bridgeHandler]

// installKlogOnce hands klogBridge to klog the first time a bridge is installed.
var installKlogOnce sync.Once

func (k klogBridge) current() slog.Handler {
	t := klogTarget.Load()
	if t == nil {
		return discardHandler{}
	}
	var h slog.Handler = *t
	for _, op := range k.ops {
		h = op(h)
	}
	return h
}

// Enabled implements slog.Handler against the current target.
func (k klogBridge) Enabled(ctx context.Context, l slog.Level) bool {
	return k.current().Enabled(ctx, l)
}

// Handle implements slog.Handler against the current target.
func (k klogBridge) Handle(ctx context.Context, r slog.Record) error {
	return k.current().Handle(ctx, r)
}

// WithAttrs implements slog.Handler by recording the step for replay.
func (k klogBridge) WithAttrs(a []slog.Attr) slog.Handler {
	return k.with(func(h slog.Handler) slog.Handler { return h.WithAttrs(a) })
}

// WithGroup implements slog.Handler by recording the step for replay.
func (k klogBridge) WithGroup(g string) slog.Handler {
	return k.with(func(h slog.Handler) slog.Handler { return h.WithGroup(g) })
}

func (k klogBridge) with(op func(slog.Handler) slog.Handler) klogBridge {
	ops := make([]func(slog.Handler) slog.Handler, len(k.ops), len(k.ops)+1)
	copy(ops, k.ops)
	return klogBridge{ops: append(ops, op)}
}

// discardHandler drops records that arrive before any bridge is installed.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler           { return d }

// InstallKlogBridge routes every record the Kubernetes libraries emit through
// klog into the root logger, so the process has one log stream in one format.
// Call it right after the root logger is built. A second call reroutes the
// bridge to the new root without touching the logger klog holds.
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

	inner := root.Handler().WithAttrs([]slog.Attr{slog.String("component", string(ComponentK8s))})
	klogTarget.Store(&bridgeHandler{inner: inner, verbosity: verbosity})
	installKlogOnce.Do(func() { klog.SetSlogLogger(slog.New(klogBridge{})) })
}
