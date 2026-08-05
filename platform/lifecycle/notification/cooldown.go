package notification

// cooldown.go extracts the per-{subject,type} notification cooldown into an
// optional shared store. The in-router map (the default) is process-local:
// in a multi-replica fleet two replicas can see the same audit event and
// both pass their own cooldown check — the user gets two emails. A shared
// store (the Redis peer in infrastructure/redis) makes the suppression
// decision cluster-wide, with the same fail-open posture: a store error is
// logged and the notification proceeds (never drop a security notice
// because the cooldown store is down).

import (
	"context"
	"time"
)

// CooldownStore atomically decides AND records one cooldown suppression.
// Suppressed returns true when the key is inside its cooldown window;
// otherwise it records until = now+cooldown and returns false (the caller
// proceeds). Implementations must be safe for concurrent use and must not
// return an error for a normal miss — errors are for store failures only.
type CooldownStore interface {
	Suppressed(ctx context.Context, key string, now time.Time, cooldown time.Duration) (bool, error)
}

// MemoryCooldownStore is the in-process reference implementation — the
// same map the router used inline, extracted so the interface has a real
// in-package peer and tests can inject a store.
type MemoryCooldownStore struct {
	recent map[string]time.Time
}

// NewMemoryCooldownStore returns an empty store.
func NewMemoryCooldownStore() *MemoryCooldownStore {
	return &MemoryCooldownStore{recent: map[string]time.Time{}}
}

// Suppressed implements CooldownStore.
func (m *MemoryCooldownStore) Suppressed(_ context.Context, key string, now time.Time, cooldown time.Duration) (bool, error) {
	if until := m.recent[key]; until.After(now) {
		return true, nil
	}
	m.recent[key] = now.Add(cooldown)
	return false, nil
}

// WithCooldownStore replaces the router's in-process cooldown map with a
// shared store. Nil/unset keeps the built-in map (byte-identical behavior);
// a nil store passed explicitly is ignored for the same reason.
func WithCooldownStore(store CooldownStore) Option {
	return func(r *Router) {
		if store != nil {
			r.cooldownStore = store
		}
	}
}
