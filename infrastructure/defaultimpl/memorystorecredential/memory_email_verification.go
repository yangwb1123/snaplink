package memorystorecredential

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryEmailVerificationStore is an in-memory core.EmailVerificationStore for
// the signup email-verification flow. Single-process only; multi-replica needs
// the sqlite peer. Consume is destructive (single-use). Keys are SHA-256 hashes
// of the raw tokens.
type MemoryEmailVerificationStore struct {
	mu     sync.RWMutex
	tokens map[string]*core.EmailVerificationToken
}

// NewMemoryEmailVerificationStore returns an empty store.
func NewMemoryEmailVerificationStore() *MemoryEmailVerificationStore {
	return &MemoryEmailVerificationStore{tokens: make(map[string]*core.EmailVerificationToken)}
}

// Issue stores a copy of the token keyed by its SHA-256 hash value.
func (m *MemoryEmailVerificationStore) Issue(_ context.Context, tok *core.EmailVerificationToken) error {
	cp := *tok
	m.mu.Lock()
	m.tokens[tok.Token] = &cp
	m.mu.Unlock()
	return nil
}

// Consume atomically deletes and returns the token by its SHA-256 hash.
// Missing or expired entries return core.ErrVerificationTokenNotFound
// (oracle-safe: caller must not distinguish causes).
func (m *MemoryEmailVerificationStore) Consume(_ context.Context, token string) (*core.EmailVerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[token]
	if !ok {
		return nil, core.ErrVerificationTokenNotFound
	}
	delete(m.tokens, token)
	if tok.IsExpired() {
		return nil, core.ErrVerificationTokenNotFound
	}
	return tok, nil
}

var (
	_ core.EmailVerificationStore = (*MemoryEmailVerificationStore)(nil)
)
