package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"sync"

	"github.com/snaplink/sso"
)

// authCodeBytes is the size in bytes of generated codes (32 → 43 base64url
// chars). Larger than the typical OAuth code; matches the temp_token
// generator so brute-force costs are consistent across one-shot tokens.
const authCodeBytes = 32

// MemoryAuthCodeStore is an in-process sso.AuthCodeStore. Production
// deployments with multiple replicas should swap a Redis or SQL backend
// — codes issued on one replica must be consumable on any other.
type MemoryAuthCodeStore struct {
	mu      sync.Mutex
	entries map[string]*sso.AuthCode
}

// NewMemoryAuthCodeStore returns a ready-to-use store with no TTL of its
// own — TTLs are stamped per-AuthCode at Issue time.
func NewMemoryAuthCodeStore() *MemoryAuthCodeStore {
	return &MemoryAuthCodeStore{entries: make(map[string]*sso.AuthCode)}
}

func (m *MemoryAuthCodeStore) Issue(_ context.Context, code string, info *sso.AuthCode) error {
	if code == "" || info == nil {
		return sso.ErrAuthCodeNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy slice to avoid aliasing caller's underlying array — a future
	// mutation of info.Scopes by the caller must not be visible at
	// Consume time.
	scopes := append([]string(nil), info.Scopes...)
	attrs := copyMap(info.Attributes)
	m.entries[code] = &sso.AuthCode{
		UserID:              info.UserID,
		ClientID:            info.ClientID,
		RedirectURI:         info.RedirectURI,
		Scopes:              scopes,
		Nonce:               info.Nonce,
		Provider:            info.Provider,
		Attributes:          attrs,
		CodeChallenge:       info.CodeChallenge,
		CodeChallengeMethod: info.CodeChallengeMethod,
		ExpiresAt:           info.ExpiresAt,
	}
	return nil
}

func (m *MemoryAuthCodeStore) Consume(_ context.Context, code string) (*sso.AuthCode, error) {
	m.mu.Lock()
	entry, ok := m.entries[code]
	delete(m.entries, code) // single-use — delete on every Consume attempt
	m.mu.Unlock()

	if !ok {
		return nil, sso.ErrAuthCodeNotFound
	}
	// Expired entries already removed above; just signal the same not-found
	// outcome so callers can't distinguish stale-vs-unknown from the wire.
	if entry.IsExpired() {
		return nil, sso.ErrAuthCodeNotFound
	}
	return entry, nil
}

// GenerateAuthCode mints a cryptographically random base64url-encoded
// code suitable for the OAuth 2.0 authorization_code grant. Exposed so
// custom AuthCodeStore implementations can reuse it.
func GenerateAuthCode() (string, error) {
	buf := make([]byte, authCodeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// copyMap returns a shallow copy of m, or nil when m is nil. Used so
// AuthCode.Attributes don't alias the caller's map.
func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	maps.Copy(out, m)
	return out
}

// Compile-time interface check.
var _ sso.AuthCodeStore = (*MemoryAuthCodeStore)(nil)
