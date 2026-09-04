// Copyright Jetstack Ltd. See LICENSE for details.

// Package hooks provides a concurrency-safe registry of named pre-shutdown
// hooks that run in registration order during graceful shutdown.
package hooks

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	k8sErrors "k8s.io/apimachinery/pkg/util/errors"

	"github.com/rafpe/kube-oidc-proxy/pkg/logging"
)

// ShutdownHook is a callback invoked during graceful shutdown.
type ShutdownHook func() error

// hookEntry pairs a hook with its registration name so hooks can run in a
// stable, deterministic order rather than the randomized order of a map range.
type hookEntry struct {
	name string
	hook ShutdownHook
}

// Hooks is a registry of named pre-shutdown hooks. It is safe for concurrent
// use.
//
// Ordering and semantics:
//   - Hooks run in registration order.
//   - Registering an already-registered name overwrites the hook in place,
//     preserving its original position (last write wins).
//   - Hooks registered while RunPreShutdownHooks is executing are not run by
//     that in-flight pass (the run operates on a snapshot).
type Hooks struct {
	// logger is the shutdown-component logger the registry reports through.
	// Never nil: New substitutes a discarding logger.
	logger *slog.Logger

	mu      sync.Mutex
	entries []hookEntry
	indexOf map[string]int
}

// New returns an empty registry reporting through logger, which the caller has
// already bound to the shutdown component. A nil logger yields one that
// discards every record, so a partially wired caller cannot panic during
// teardown.
func New(logger *slog.Logger) *Hooks {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Hooks{
		logger:  logger,
		indexOf: make(map[string]int),
	}
}

// AddPreShutdownHook registers hook under name. If name is already registered
// its hook is replaced in place, preserving registration order.
func (h *Hooks) AddPreShutdownHook(name string, hook ShutdownHook) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if i, ok := h.indexOf[name]; ok {
		h.entries[i].hook = hook
		return
	}

	h.indexOf[name] = len(h.entries)
	h.entries = append(h.entries, hookEntry{name: name, hook: hook})
}

// RunPreShutdownHooks runs every registered pre-shutdown hook in registration
// order and returns an aggregate of any failures.
//
// The registered hooks are snapshotted under the lock and then invoked WITHOUT
// the lock held: a slow or blocking hook must not stall other registry
// operations, and a hook that touches the registry must not deadlock. One
// hook's failure does not prevent later hooks from running; each failure is
// wrapped with %w so the cause remains inspectable via errors.Is through the
// returned aggregate.
//
// Every hook reports its own outcome as it finishes, so a shutdown that takes
// too long names the hook responsible rather than leaving one aggregate error
// at the end.
func (h *Hooks) RunPreShutdownHooks() error {
	h.mu.Lock()
	snapshot := make([]hookEntry, len(h.entries))
	copy(snapshot, h.entries)
	h.mu.Unlock()

	ctx := context.Background()

	var errs []error
	for _, entry := range snapshot {
		start := time.Now()
		err := entry.hook()
		elapsed := time.Since(start)

		// The hook's own error is reported, not the aggregate wrapping below:
		// the hook name is already its own field.
		if err != nil {
			logging.Emit(ctx, h.logger, logging.EventProxyHookFailed,
				slog.String("hook", logging.Bound(entry.name, logging.MaxIdentity)),
				slog.Int64("duration_ms", elapsed.Milliseconds()),
				logging.ErrAttr(err))
			errs = append(errs, fmt.Errorf("PreShutdownHook %q failed: %w", entry.name, err))
			continue
		}

		logging.Emit(ctx, h.logger, logging.EventProxyHookCompleted,
			slog.String("hook", logging.Bound(entry.name, logging.MaxIdentity)),
			slog.Int64("duration_ms", elapsed.Milliseconds()))
	}

	return k8sErrors.NewAggregate(errs)
}
