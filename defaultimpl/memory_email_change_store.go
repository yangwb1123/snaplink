package defaultimpl

import (
	"context"
	"sync"

	"github.com/snaplink/sso/core"
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

var _ core.EmailChangeStore = (*MemoryEmailChangeStore)(nil)
