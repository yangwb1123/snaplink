package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/snaplink/sso"
)

// refreshTokenBytes is the size in bytes of generated refresh tokens
// (32 → 43 base64url chars). Refresh tokens live for days/weeks so the
// brute-force surface is larger than for auth codes — 256 bits of
// entropy keeps a fleet-wide guess infeasible even at scale.
const refreshTokenBytes = 32

// MemoryRefreshTokenStore is an in-process sso.RefreshTokenStore.
// Production deployments with multiple replicas should swap a Redis,
// SQL, or other shared backend — tokens issued on one replica must be
// consumable on any other, and persistence across restarts is usually
// expected (a server restart shouldn't log every user out).
type MemoryRefreshTokenStore struct {
	mu      sync.Mutex
	entries map[string]*sso.RefreshToken
}

// NewMemoryRefreshTokenStore returns a ready-to-use store with no TTL
// of its own — TTLs are stamped per-RefreshToken at Issue time.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{entries: make(map[string]*sso.RefreshToken)}
}

func (m *MemoryRefreshTokenStore) Issue(_ context.Context, token string, info *sso.RefreshToken) error {
	if token == "" || info == nil {
		return sso.ErrRefreshTokenNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy slice to avoid aliasing caller's underlying array — a future
	// mutation of info.Scopes by the caller must not be visible at
	// Consume time.
	scopes := append([]string(nil), info.Scopes...)
	attrs := copyMap(info.Attributes)
	m.entries[token] = &sso.RefreshToken{
		UserID:     info.UserID,
		ClientID:   info.ClientID,
		Provider:   info.Provider,
		Scopes:     scopes,
		Attributes: attrs,
		IssuedAt:   info.IssuedAt,
		ExpiresAt:  info.ExpiresAt,
	}
	return nil
}

func (m *MemoryRefreshTokenStore) Consume(_ context.Context, token string) (*sso.RefreshToken, error) {
	m.mu.Lock()
	entry, ok := m.entries[token]
	delete(m.entries, token) // single-use rotation — delete on every Consume attempt
	m.mu.Unlock()

	if !ok {
		return nil, sso.ErrRefreshTokenNotFound
	}
	// Expired entries already removed above; just signal the same
	// not-found outcome so callers can't distinguish stale-vs-unknown
	// from the wire.
	if entry.IsExpired() {
		return nil, sso.ErrRefreshTokenNotFound
	}
	return entry, nil
}

// Inspect returns the token's payload without consuming it. Required
// by /token/introspect to answer non-destructive queries. Returns
// ErrRefreshTokenNotFound for unknown / expired tokens (same oracle-
// resistant indistinguishability as Consume).
func (m *MemoryRefreshTokenStore) Inspect(_ context.Context, token string) (*sso.RefreshToken, error) {
	m.mu.Lock()
	entry, ok := m.entries[token]
	m.mu.Unlock()
	if !ok {
		return nil, sso.ErrRefreshTokenNotFound
	}
	if entry.IsExpired() {
		// Lazy GC of expired entries — keeps the map from
		// accumulating stale keys without a sweeper goroutine.
		m.mu.Lock()
		delete(m.entries, token)
		m.mu.Unlock()
		return nil, sso.ErrRefreshTokenNotFound
	}
	return entry, nil
}

// Delete removes a token without going through Consume's rotation
// path. Idempotent per RFC 7009 §2.2 — deleting an unknown token
// returns nil.
func (m *MemoryRefreshTokenStore) Delete(_ context.Context, token string) error {
	m.mu.Lock()
	delete(m.entries, token)
	m.mu.Unlock()
	return nil
}

// GenerateRefreshToken mints a cryptographically random base64url-encoded
// token suitable for the OAuth 2.0 refresh_token grant. Exposed so
// custom RefreshTokenStore implementations can reuse it.
func GenerateRefreshToken() (string, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Compile-time interface checks.
var (
	_ sso.RefreshTokenStore     = (*MemoryRefreshTokenStore)(nil)
	_ sso.RefreshTokenInspector = (*MemoryRefreshTokenStore)(nil)
)
