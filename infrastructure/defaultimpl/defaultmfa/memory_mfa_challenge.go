package defaultmfa

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

// MemoryMFAChallengeStore is the in-process [spi.MFAChallengeStore].
// Single-replica deploys + tests; cluster deploys want the SQLite
// (or Redis, when that lands) peer so a challenge issued by replica A
// can be consumed by replica B.
//
// Race-free Consume via map delete + return-if-found-and-fresh — the
// same pattern MemoryAuthCodeStore / MemoryDeviceCodeStore use.
type MemoryMFAChallengeStore struct {
	mu        sync.Mutex
	entries   map[string]*spi.MFAChallenge
	lastSweep atomic.Int64
}

// NewMemoryMFAChallengeStore builds an empty MFA challenge store.
func NewMemoryMFAChallengeStore() *MemoryMFAChallengeStore {
	return &MemoryMFAChallengeStore{entries: make(map[string]*spi.MFAChallenge)}
}

// Put persists c keyed by c.ID. Caller MUST set both ID and ExpiresAt;
// the store performs no defaulting (default-TTL policy lives in the
// SSO server so memory + sqlite peers stay schema-flat).
func (m *MemoryMFAChallengeStore) Put(_ context.Context, c *spi.MFAChallenge) error {
	if c == nil || c.ID == "" {
		return spi.ErrMFAChallengeNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	nowNanos := now.UnixNano()
	previous := m.lastSweep.Load()
	if nowNanos-previous >= int64(sweepInterval) &&
		m.lastSweep.CompareAndSwap(previous, nowNanos) {
		sweepExpiredEntries(m.entries, now, func(entry *spi.MFAChallenge) time.Time {
			return entry.ExpiresAt
		})
	}
	// Copy the opaque resume blob as well as the struct. It contains the
	// authentication state resumed after MFA and must not remain caller-owned.
	m.entries[c.ID] = cloneMFAChallenge(c)
	return nil
}

func cloneMFAChallenge(challenge *spi.MFAChallenge) *spi.MFAChallenge {
	if challenge == nil {
		return nil
	}
	copy := *challenge
	copy.RequestState = slices.Clone(challenge.RequestState)
	return &copy
}

// Consume atomically deletes + returns the matching challenge.
// Missing / expired / already-consumed → ErrMFAChallengeNotFound.
// Anti-enumeration: caller MUST collapse all three to one wire shape.
func (m *MemoryMFAChallengeStore) Consume(_ context.Context, id string) (*spi.MFAChallenge, error) {
	if id == "" {
		return nil, spi.ErrMFAChallengeNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	if !ok {
		return nil, spi.ErrMFAChallengeNotFound
	}
	delete(m.entries, id)
	// Single-use semantic: even if the caller's clock disagrees with
	// ExpiresAt, the entry is gone now. Re-checking expiry here keeps
	// the wire contract consistent with the SQLite peer which prunes
	// expired rows lazily on Consume too.
	if time.Since(entry.ExpiresAt) > 0 {
		return nil, spi.ErrMFAChallengeNotFound
	}
	return entry, nil
}
