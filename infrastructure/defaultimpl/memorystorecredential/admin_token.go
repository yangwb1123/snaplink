package memorystorecredential

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/core"
)

var ErrTokenNotFound = errors.New("sso: admin token not found")

// MemoryAdminTokenStore is an in-process, non-persistent admin token
// store. Suitable for single-replica dev and test.
type MemoryAdminTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]core.AdminToken
}

// NewMemoryAdminTokenStore returns an empty MemoryAdminTokenStore.
func NewMemoryAdminTokenStore() *MemoryAdminTokenStore {
	return &MemoryAdminTokenStore{
		tokens: make(map[string]core.AdminToken),
	}
}

func (s *MemoryAdminTokenStore) Record(_ context.Context, token core.AdminToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.ID] = token
	return nil
}

func (s *MemoryAdminTokenStore) GetByID(_ context.Context, id string) (core.AdminToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	if !ok {
		return core.AdminToken{}, ErrTokenNotFound
	}
	if !t.ExpiresAt.IsZero() && time.Since(t.ExpiresAt) > 0 {
		return core.AdminToken{}, ErrTokenNotFound
	}
	return t, nil
}

func (s *MemoryAdminTokenStore) List(_ context.Context, adminID string) ([]core.AdminToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]core.AdminToken, 0, len(s.tokens))
	for _, t := range s.tokens {
		if !t.ExpiresAt.IsZero() && time.Since(t.ExpiresAt) > 0 {
			continue
		}
		if adminID != "" && t.AdminID != adminID {
			continue
		}
		result = append(result, t)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	return result, nil
}

func (s *MemoryAdminTokenStore) Revoke(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Anti-enumeration: no-op when unknown.
	if _, ok := s.tokens[id]; ok {
		delete(s.tokens, id)
	}
	return nil
}

func (s *MemoryAdminTokenStore) Touch(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil
	}
	t.LastUsedAt = time.Now()
	s.tokens[id] = t
	return nil
}

var _ core.AdminTokenStore = (*MemoryAdminTokenStore)(nil)
