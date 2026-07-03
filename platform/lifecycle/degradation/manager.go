package degradation

import (
	"context"
	"sync"
	"sync/atomic"
)

// ChangeFunc observes a completed mode transition. It runs OUTSIDE the
// Manager's internal lock so a hook may safely call back into the Manager (or
// block on I/O such as an audit sink) without risking a deadlock. The ctx is
// the one passed to [Manager.SetMode] so a hook can extract the acting admin /
// request correlation from it.
type ChangeFunc func(ctx context.Context, from, to Mode, reason string)

// Manager holds the process-wide degraded-service mode. Reads (Mode) are
// lock-free via an atomic pointer so the per-request enforcement gate adds no
// contention on the hot path; writes (SetMode) serialize on a mutex so a
// transition and its change-hook fan-out are observed atomically and each hook
// sees a consistent from/to pair. Manager is the in-memory implementation of
// [Controller]; there is no separate persisted backend — the mode is
// deliberately ephemeral per replica (a restart returns to its configured
// initial mode, and a cluster drives every replica via its own health loop or
// admin call).
type Manager struct {
	mu    sync.Mutex // serializes SetMode + hook registration
	cur   atomic.Pointer[Mode]
	hooks []ChangeFunc
}

// NewManager returns a Manager starting in initial. An invalid initial mode
// falls back to ModeNormal so a misconfiguration can never boot the server into
// an unknown, request-shedding posture.
func NewManager(initial Mode) *Manager {
	if !initial.Valid() {
		initial = ModeNormal
	}
	m := &Manager{}
	m.cur.Store(&initial)
	return m
}

// Mode returns the currently active mode. Lock-free; safe from any goroutine.
func (m *Manager) Mode() Mode {
	if p := m.cur.Load(); p != nil {
		return *p
	}
	return ModeNormal
}

// OnChange registers a hook invoked after every mode transition. Hooks fire in
// registration order. A nil hook is ignored. Register hooks before the server
// begins serving; the audit + metric side effects are wired this way.
func (m *Manager) OnChange(hook ChangeFunc) {
	if hook == nil {
		return
	}
	m.mu.Lock()
	m.hooks = append(m.hooks, hook)
	m.mu.Unlock()
}

// SetMode switches the active mode to to and fires every registered change
// hook. It reports whether the mode actually changed (a no-op transition to the
// current mode returns changed=false and fires no hook, so a health loop can
// call it every tick without spamming audit). An invalid target returns
// ErrInvalidMode and leaves the mode untouched.
func (m *Manager) SetMode(ctx context.Context, to Mode, reason string) (changed bool, err error) {
	if !to.Valid() {
		return false, ErrInvalidMode
	}
	m.mu.Lock()
	from := m.Mode()
	if from == to {
		m.mu.Unlock()
		return false, nil
	}
	target := to
	m.cur.Store(&target)
	// Snapshot hooks under the lock, fire them outside it: a hook that blocks
	// (audit sink) or re-enters (reads Mode) must not hold up other writers.
	hooks := make([]ChangeFunc, len(m.hooks))
	copy(hooks, m.hooks)
	m.mu.Unlock()

	for _, h := range hooks {
		h(ctx, from, to, reason)
	}
	return true, nil
}
