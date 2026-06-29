package memorystorecredential

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryEmailVerificationStore is an in-memory core.EmailVerificationStore for
// the signup email-verification flow. Single-process only; multi-replica needs
// the sqlite peer. Consume is destructive (single-use). Keys are SHA-256 hashes
// of the raw tokens. A secondary username index enables RevokeByUsername.
type MemoryEmailVerificationStore struct {
	mu            sync.RWMutex
	tokens        map[string]*core.EmailVerificationToken // hash → token
	usernameIndex map[string]string                       // username → hash (latest)
}

// NewMemoryEmailVerificationStore returns an empty store.
func NewMemoryEmailVerificationStore() *MemoryEmailVerificationStore {
	return &MemoryEmailVerificationStore{
		tokens:        make(map[string]*core.EmailVerificationToken),
		usernameIndex: make(map[string]string),
	}
}

// Issue stores a copy of the token keyed by its SHA-256 hash value and updates
// the username secondary index. A prior pending token for the same username is
// silently overwritten (only the latest token is valid after re-issue).
// Lazy GC: expired entries are swept from both maps before each insert so the
// store stays bounded by the count of non-expired tokens (no background goroutine
// required; same pattern as MemoryJTIReplayStore).
func (m *MemoryEmailVerificationStore) Issue(_ context.Context, tok *core.EmailVerificationToken) error {
	cp := *tok
	m.mu.Lock()
	// Sweep expired entries before inserting. Bounded by O(n) on active window;
	// n is small for any realistic registration rate * token-TTL product.
	for hash, t := range m.tokens {
		if t.IsExpired() {
			delete(m.usernameIndex, t.Username)
			delete(m.tokens, hash)
		}
	}
	if old, ok := m.usernameIndex[tok.Username]; ok {
		delete(m.tokens, old)
	}
	m.tokens[tok.Token] = &cp
	m.usernameIndex[tok.Username] = tok.Token
	m.mu.Unlock()
	return nil
}

// RevokeByUsername deletes any pending token for username. Satisfies
// core.EmailVerificationRevoker; idempotent (returns 0, nil if none exists).
func (m *MemoryEmailVerificationStore) RevokeByUsername(_ context.Context, username string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hash, ok := m.usernameIndex[username]
	if !ok {
		return 0, nil
	}
	delete(m.tokens, hash)
	delete(m.usernameIndex, username)
	return 1, nil
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
	delete(m.usernameIndex, tok.Username)
	if tok.IsExpired() {
		return nil, core.ErrVerificationTokenNotFound
	}
	return tok, nil
}

var (
	_ core.EmailVerificationStore   = (*MemoryEmailVerificationStore)(nil)
	_ core.EmailVerificationRevoker = (*MemoryEmailVerificationStore)(nil)
)
