// Package noop is the default lock backend — it pretends to hold every
// lock immediately. Use only when you have ONE bootstrap runner. The
// Runner wires this when no Lock is configured, so existing single-node
// callers see no behavior change.
package noop

import (
	"context"
	"time"

	"github.com/snaplink/sso/bootstrap/lock"
)

// Lock is the no-op Lock. Always succeeds; FencingToken is always 0.
type Lock struct{}

// New returns a noop Lock. Stateless — safe to share / construct anywhere.
func New() *Lock { return &Lock{} }

func (l *Lock) TryAcquire(_ context.Context, _ string, _ time.Duration) (lock.Handle, error) {
	return &handle{}, nil
}

type handle struct{}

func (h *handle) Renew(context.Context) error    { return nil }
func (h *handle) Release(context.Context) error  { return nil }
func (h *handle) FencingToken() uint64           { return 0 }

// Compile-time interface assertions.
var (
	_ lock.Lock   = (*Lock)(nil)
	_ lock.Handle = (*handle)(nil)
)
