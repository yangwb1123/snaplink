package defaultimpl

import (
	"context"
	"sync"

	"github.com/snaplink/sso/core"
)

// MemoryPasswordResetStore is an in-memory core.PasswordResetStore for the
// forgot-password flow. Single-process only; multi-replica needs the sqlite
// peer. Consume is destructive (single-use).
type MemoryPasswordResetStore struct {
	mu     sync.Mutex
	tokens map[string]*core.PasswordResetToken
}

// NewMemoryPasswordResetStore returns an empty store.
func NewMemoryPasswordResetStore() *MemoryPasswordResetStore {
	return &MemoryPasswordResetStore{tokens: make(map[string]*core.PasswordResetToken)}
}

// Issue stores a copy of the token keyed by its value.
func (m *MemoryPasswordResetStore) Issue(_ context.Context, rt *core.PasswordResetToken) error {
	cp := *rt
	m.mu.Lock()
	m.tokens[rt.Token] = &cp
	m.mu.Unlock()
	return nil
}

// Consume atomically deletes and returns the token. Missing or expired entries
// return core.ErrResetTokenNotFound (expired rows are deleted).
func (m *MemoryPasswordResetStore) Consume(_ context.Context, token string) (*core.PasswordResetToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rt, ok := m.tokens[token]
	if !ok {
		return nil, core.ErrResetTokenNotFound
	}
	delete(m.tokens, token)
	if rt.IsExpired() {
		return nil, core.ErrResetTokenNotFound
	}
	return rt, nil
}

// RevokeByUser deletes all pending reset tokens bound to userID (admin-plane
// invalidation) and returns the count removed.
func (m *MemoryPasswordResetStore) RevokeByUser(_ context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for tok, rt := range m.tokens {
		if rt.UserID == userID {
			delete(m.tokens, tok)
			n++
		}
	}
	return n, nil
}

var (
	_ core.PasswordResetStore   = (*MemoryPasswordResetStore)(nil)
	_ core.PasswordResetRevoker = (*MemoryPasswordResetStore)(nil)
)
