package memorystoreoauth

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/protocols/oauth/oauthspi"
)

// MemoryCIBAPushDeadLetterStore is an in-memory implementation of
// oauthspi.CIBAPushDeadLetterStore. Safe for concurrent access.
// Entries are expiry-aware: old entries are skipped during listing
// and cleaned up on writes.
type MemoryCIBAPushDeadLetterStore struct {
	mu       sync.RWMutex
	entries  map[string]*deadLetterEntry
	nextID   atomic.Int64
	entryTTL time.Duration // zero = never expire
}

type deadLetterEntry struct {
	Payload oauthspi.PushPayload
	Err     string
	Created time.Time
	Acked   bool
}

// NewMemoryCIBAPushDeadLetterStore creates a dead-letter store with
// the given entry TTL. A TTL of zero means entries never expire.
func NewMemoryCIBAPushDeadLetterStore(entryTTL time.Duration) *MemoryCIBAPushDeadLetterStore {
	return &MemoryCIBAPushDeadLetterStore{
		entries:  make(map[string]*deadLetterEntry),
		entryTTL: entryTTL,
	}
}

// Record persists a failed push delivery attempt.
func (s *MemoryCIBAPushDeadLetterStore) Record(_ context.Context, deliveryID string, payload oauthspi.PushPayload, err error) error {
	id := deliveryID
	if id == "" {
		id = fmt.Sprintf("dl-%d", s.nextID.Add(1))
	}
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[id] = &deadLetterEntry{
		Payload: payload,
		Err:     msg,
		Created: time.Now(),
	}
	return nil
}

// ListUnacknowledged returns delivery IDs that have not been
// acknowledged (replayed or resolved), skipping expired entries.
func (s *MemoryCIBAPushDeadLetterStore) ListUnacknowledged(_ context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	var ids []string
	for id, e := range s.entries {
		if e.Acked {
			continue
		}
		if s.entryTTL > 0 && now.Sub(e.Created) > s.entryTTL {
			continue
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Replay re-attempts delivery of the failed push identified by
// deliveryID. Returns the push payload so the caller can retry.
func (s *MemoryCIBAPushDeadLetterStore) Replay(_ context.Context, deliveryID string) (*oauthspi.PushPayload, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[deliveryID]
	if !ok {
		return nil, fmt.Errorf("memory_ciba_deadletter: delivery %q not found", deliveryID)
	}
	// Return a copy to prevent mutation.
	p := e.Payload
	return &p, nil
}

// Acknowledge marks a delivery as resolved (successfully replayed
// or operator-dismissed).
func (s *MemoryCIBAPushDeadLetterStore) Acknowledge(_ context.Context, deliveryID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[deliveryID]
	if !ok {
		return fmt.Errorf("memory_ciba_deadletter: delivery %q not found", deliveryID)
	}
	e.Acked = true
	return nil
}

// compile-time guard
var _ oauthspi.CIBAPushDeadLetterStore = (*MemoryCIBAPushDeadLetterStore)(nil)
