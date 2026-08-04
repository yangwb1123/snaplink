package login

import (
	"context"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/spi"
)

// MemoryTransactionStore is the single-replica default for one-time login
// continuations. It implements spi.MFAChallengeStore because both records have
// the same opaque ID, subject/client binding, expiry, and atomic-consume needs.
type MemoryTransactionStore struct {
	mu      sync.Mutex
	entries map[string]*spi.MFAChallenge
}

func NewMemoryTransactionStore() *MemoryTransactionStore {
	return &MemoryTransactionStore{entries: make(map[string]*spi.MFAChallenge)}
}

func (s *MemoryTransactionStore) Put(_ context.Context, item *spi.MFAChallenge) error {
	if item == nil || item.ID == "" {
		return spi.ErrMFAChallengeNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *item
	copy.RequestState = append([]byte(nil), item.RequestState...)
	s.entries[item.ID] = &copy
	return nil
}

func (s *MemoryTransactionStore) Consume(
	_ context.Context, id string,
) (*spi.MFAChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.entries[id]
	if !ok {
		return nil, spi.ErrMFAChallengeNotFound
	}
	delete(s.entries, id)
	if time.Since(item.ExpiresAt) > 0 {
		return nil, spi.ErrMFAChallengeNotFound
	}
	return item, nil
}
