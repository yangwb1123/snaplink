package memorystorecredential

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/security"
)

// MemoryJTIReplayStore is an in-process [security.JTIReplayStore]. Pure
// map + mutex; lazily evicts expired entries on every MarkSeen so the
// map stays bounded by the active-window key count (no background
// goroutine, no eviction lag past the first MarkSeen call after the
// expiry has passed).
//
// Multi-replica deployments need a shared backend (Redis, Memcached,
// etc.) — a jti seen by replica A is unknown to replica B with this
// implementation, defeating the defense.
type MemoryJTIReplayStore struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func NewMemoryJTIReplayStore() *MemoryJTIReplayStore {
	return &MemoryJTIReplayStore{entries: make(map[string]time.Time)}
}

func (m *MemoryJTIReplayStore) MarkSeen(_ context.Context, jti string, expiresAt time.Time) (bool, error) {
	if jti == "" {
		return true, nil
	}
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	// Lazy GC: every call sweeps any entries whose expiry has
	// passed. Bounded by O(n) on the active window; n stays small
	// for any realistic JAR/DPoP request rate * window product.
	for k, exp := range m.entries {
		if !exp.After(now) {
			delete(m.entries, k)
		}
	}
	if existing, ok := m.entries[jti]; ok {
		// Still within window → replay.
		if existing.After(now) {
			return false, nil
		}
	}
	if expiresAt.Before(now) {
		// Expiry already past — caller's clock is off OR the JWT
		// has an exp claim that's already elapsed. Either way the
		// JWT will fail other gates; recording it briefly so an
		// immediate replay (same ms) still gets caught.
		expiresAt = now.Add(time.Second)
	}
	m.entries[jti] = expiresAt
	return true, nil
}

// Forget releases a previously MarkSeen jti so a retried request carrying it is
// admitted rather than dropped as a replay (security.JTIReplayForgetter). Used
// by the CAEP receiver to roll back the jti when a fail-closed mark was followed
// by a retryable action failure. Idempotent — forgetting an unknown jti is a
// no-op.
func (m *MemoryJTIReplayStore) Forget(_ context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	m.mu.Lock()
	delete(m.entries, jti)
	m.mu.Unlock()
	return nil
}

var (
	_ security.JTIReplayStore     = (*MemoryJTIReplayStore)(nil)
	_ security.JTIReplayForgetter = (*MemoryJTIReplayStore)(nil)
)
