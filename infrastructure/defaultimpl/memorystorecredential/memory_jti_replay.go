package memorystorecredential

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/shared/security"
)

// ErrJTIStoreAtCapacity is returned by MarkSeen when MaxEntries is set
// and the store is full of still-live (unexpired) entries — see
// MemoryJTIReplayStore.MaxEntries. Every MarkSeen caller in this codebase
// already treats a non-nil error via the existing fail-open (default) /
// fail-closed (opt-in) contract (AGENTS.md "Fail Modes"), so this needs
// no new caller-side handling.
var ErrJTIStoreAtCapacity = errors.New("memorystorecredential: jti replay store at capacity")

// MemoryJTIReplayStore is an in-process [security.JTIReplayStore]. Pure
// map + mutex; lazily evicts expired entries on every MarkSeen so the
// map stays bounded by the active-window key count (no background
// goroutine, no eviction lag past the first MarkSeen call after the
// expiry has passed).
//
// MaxEntries (0 = unbounded, the default) and StartReaper are optional,
// defense-in-depth additions on top of that lazy sweep: MaxEntries caps
// growth from a pure-flood attack that outpaces the window's natural
// expiry, and StartReaper closes the one gap lazy-only GC can't reach —
// an idle store (no MarkSeen calls at all) never sweeps on its own.
// Neither changes behavior unless explicitly configured. Set MaxEntries
// and call StartReaper BEFORE the store sees traffic, matching
// MemoryRefreshTokenStore's "configure before traffic" discipline.
//
// Multi-replica deployments need a shared backend (Redis, Memcached,
// etc.) — a jti seen by replica A is unknown to replica B with this
// implementation, defeating the defense.
type MemoryJTIReplayStore struct {
	MaxEntries int

	mu      sync.Mutex
	entries map[string]time.Time
	reaper  *memreaper.Reaper
}

func NewMemoryJTIReplayStore() *MemoryJTIReplayStore {
	return &MemoryJTIReplayStore{entries: make(map[string]time.Time)}
}

// StartReaper launches a background sweep of expired entries every
// interval, on top of MarkSeen's existing per-call lazy sweep — covers a
// store that has gone idle (no MarkSeen calls to trigger the lazy path).
// A non-positive interval is a no-op. Idempotent: calling it again stops
// the previous reaper first, so a caller can't leak a goroutine by
// calling it twice.
func (m *MemoryJTIReplayStore) StartReaper(interval time.Duration) {
	_ = m.reaper.Close()
	m.reaper = memreaper.Start(interval, m.sweepExpired)
}

// Close stops the background reaper started via StartReaper, if any. A
// store that never called StartReaper has nothing to stop.
func (m *MemoryJTIReplayStore) Close() error {
	return m.reaper.Close()
}

func (m *MemoryJTIReplayStore) sweepExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, exp := range m.entries {
		if !exp.After(now) {
			delete(m.entries, k)
		}
	}
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
	} else if m.MaxEntries > 0 && len(m.entries) >= m.MaxEntries {
		// Capacity guard only applies to a brand-new key — the sweep
		// above already dropped anything expired, so remaining entries
		// are all genuinely live. Re-marking an existing key never grows
		// the map, so it's exempt from the cap.
		return false, ErrJTIStoreAtCapacity
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
	_ io.Closer                   = (*MemoryJTIReplayStore)(nil)
)
