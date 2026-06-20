package memorystorecredential

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryEmailChangeStore is an in-memory core.EmailChangeStore for the
// verified-email-change flow. Single-process only; multi-replica needs the
// sqlite peer. Consume is destructive (single-use).
type MemoryEmailChangeStore struct {
	mu     sync.Mutex
	tokens map[string]*core.EmailChangeToken
}

// NewMemoryEmailChangeStore returns an empty store.
func NewMemoryEmailChangeStore() *MemoryEmailChangeStore {
	return &MemoryEmailChangeStore{tokens: make(map[string]*core.EmailChangeToken)}
}

// Issue stores a copy of the token keyed by its value.
func (m *MemoryEmailChangeStore) Issue(_ context.Context, tok *core.EmailChangeToken) error {
	cp := *tok
	m.mu.Lock()
	m.tokens[tok.Token] = &cp
	m.mu.Unlock()
	return nil
}

// Consume atomically deletes and returns the token. Missing or expired entries
// return core.ErrEmailChangeTokenNotFound (expired rows are deleted).
func (m *MemoryEmailChangeStore) Consume(_ context.Context, token string) (*core.EmailChangeToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[token]
	if !ok {
		return nil, core.ErrEmailChangeTokenNotFound
	}
	delete(m.tokens, token)
	if tok.IsExpired() {
		return nil, core.ErrEmailChangeTokenNotFound
	}
	return tok, nil
}

// RevokeByUser deletes all pending email-change tokens bound to userID
// (admin-plane invalidation) and returns the count removed.
func (m *MemoryEmailChangeStore) RevokeByUser(_ context.Context, userID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for tok, ec := range m.tokens {
		if ec.UserID == userID {
			delete(m.tokens, tok)
			n++
		}
	}
	return n, nil
}

// ListByUser returns all pending email-change tokens bound to userID
// (admin-plane read; the caller projects safe metadata only).
func (m *MemoryEmailChangeStore) ListByUser(_ context.Context, userID string) ([]*core.EmailChangeToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*core.EmailChangeToken
	for _, ec := range m.tokens {
		if ec.UserID == userID {
			cp := *ec
			out = append(out, &cp)
		}
	}
	return out, nil
}

var (
	_ core.EmailChangeStore   = (*MemoryEmailChangeStore)(nil)
	_ core.EmailChangeRevoker = (*MemoryEmailChangeStore)(nil)
	_ core.EmailChangeLister  = (*MemoryEmailChangeStore)(nil)
)
