// Copyright Jetstack Ltd. See LICENSE for details.
package hooks

import (
	"fmt"
	"sync"

	k8sErrors "k8s.io/apimachinery/pkg/util/errors"
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
	mu      sync.Mutex
	entries []hookEntry
	indexOf map[string]int
}

func New() *Hooks {
	return &Hooks{
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
func (h *Hooks) RunPreShutdownHooks() error {
	h.mu.Lock()
	snapshot := make([]hookEntry, len(h.entries))
	copy(snapshot, h.entries)
	h.mu.Unlock()

	var errs []error
	for _, entry := range snapshot {
		if err := entry.hook(); err != nil {
			errs = append(errs, fmt.Errorf("PreShutdownHook %q failed: %w", entry.name, err))
		}
	}

	return k8sErrors.NewAggregate(errs)
}
