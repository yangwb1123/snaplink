// Package memory is the in-process bootstrap.Tracker, suitable for tests.
package memory

import (
	"context"
	"sync"

	"github.com/snaplink/sso/bootstrap"
)

// Tracker is an in-memory bootstrap.Tracker. State is lost on restart —
// fine for tests, NOT for real boot sequences (every restart re-runs every
// step).
type Tracker struct {
	mu      sync.Mutex
	applied map[string]int // namespace -> highest version
}

func New() *Tracker { return &Tracker{applied: make(map[string]int)} }

func (t *Tracker) AppliedVersion(_ context.Context, namespace string) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.applied[namespace], nil
}

func (t *Tracker) MarkApplied(_ context.Context, namespace string, version int, _ string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if version > t.applied[namespace] {
		t.applied[namespace] = version
	}
	return nil
}

func (t *Tracker) Close() error { return nil }

// Compile-time interface check.
var _ bootstrap.Tracker = (*Tracker)(nil)
