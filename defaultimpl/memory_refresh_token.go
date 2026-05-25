package defaultimpl

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"sync"
)

// refreshTokenBytes is the size in bytes of generated refresh tokens
// (32 → 43 base64url chars). Refresh tokens live for days/weeks so the
// brute-force surface is larger than for auth codes — 256 bits of
// entropy keeps a fleet-wide guess infeasible even at scale.
const refreshTokenBytes = 32

// MemoryRefreshTokenStore is an in-process oauth.RefreshTokenStore.
// Production deployments with multiple replicas should swap a Redis,
// SQL, or other shared backend — tokens issued on one replica must be
// consumable on any other, and persistence across restarts is usually
// expected (a server restart shouldn't log every user out).
//
// Implements oauth.RefreshTokenFamilyTracker (OAuth Security BCP §4.13):
// every Issue stamps the token's FamilyID into `families` so a
// replay-after-rotation Consume can detect the reuse and let the
// handler kill every sibling token via DeleteFamily. The reuse
// memory persists until DeleteFamily is called (or the entire store
// is dropped).
type MemoryRefreshTokenStore struct {
	mu       sync.Mutex
	entries  map[string]*oauth.RefreshToken
	families map[string]string // token → familyID, KEPT after Consume for reuse detection
}

// NewMemoryRefreshTokenStore returns a ready-to-use store with no TTL
// of its own — TTLs are stamped per-oauth.RefreshToken at Issue time.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{
		entries:  make(map[string]*oauth.RefreshToken),
		families: make(map[string]string),
	}
}

func (m *MemoryRefreshTokenStore) Issue(_ context.Context, token string, info *oauth.RefreshToken) error {
	if token == "" || info == nil {
		return oauth.ErrRefreshTokenNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Copy slice to avoid aliasing caller's underlying array — a future
	// mutation of info.Scopes by the caller must not be visible at
	// Consume time.
	scopes := append([]string(nil), info.Scopes...)
	resources := append([]string(nil), info.Resources...)
	attrs := copyMap(info.Attributes)
	m.entries[token] = &oauth.RefreshToken{
		UserID:               info.UserID,
		ClientID:             info.ClientID,
		Provider:             info.Provider,
		Scopes:               scopes,
		Attributes:           attrs,
		IssuedAt:             info.IssuedAt,
		ExpiresAt:            info.ExpiresAt,
		FamilyID:             info.FamilyID,
		Resources:            resources,
		AuthorizationDetails: cloneRawBytes(info.AuthorizationDetails),
		SID:                  info.SID,
	}
	// Stamp the family even when active so reuse detection works after
	// the leaf is consumed.
	if info.FamilyID != "" {
		m.families[token] = info.FamilyID
	}
	return nil
}

func (m *MemoryRefreshTokenStore) Consume(_ context.Context, token string) (*oauth.RefreshToken, error) {
	m.mu.Lock()
	entry, ok := m.entries[token]
	delete(m.entries, token) // single-use rotation — delete on every Consume attempt
	knownFamily, replayed := "", false
	if !ok {
		// Already-consumed lookup hits the families map even though the
		// active entry is gone. The handler maps oauth.ErrRefreshTokenReused
		// to the same wire error as oauth.ErrRefreshTokenNotFound but ALSO
		// kills the family before returning.
		knownFamily, replayed = m.families[token]
	}
	m.mu.Unlock()

	if !ok {
		if replayed && knownFamily != "" {
			return &oauth.RefreshToken{FamilyID: knownFamily}, oauth.ErrRefreshTokenReused
		}
		return nil, oauth.ErrRefreshTokenNotFound
	}
	// Expired entries already removed above; just signal the same
	// not-found outcome so callers can't distinguish stale-vs-unknown
	// from the wire.
	if entry.IsExpired() {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	return entry, nil
}

// DeleteFamily kills every active refresh token sharing the supplied
// FamilyID and forgets every reuse-detection marker for the family.
// Returns the count of active tokens that were removed; the bookkeeping
// entries in the families map don't count toward the returned total
// (they're noise, not user-facing state).
//
// Idempotent — deleting an unknown family returns (0, nil).
func (m *MemoryRefreshTokenStore) DeleteFamily(_ context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int
	for tok, entry := range m.entries {
		if entry.FamilyID == familyID {
			delete(m.entries, tok)
			n++
		}
	}
	// Also forget the consumed-token markers so this family can never
	// trigger a stale reuse-detection event after deletion.
	for tok, fid := range m.families {
		if fid == familyID {
			delete(m.families, tok)
		}
	}
	return n, nil
}

// Inspect returns the token's payload without consuming it. Required
// by /token/introspect to answer non-destructive queries. Returns
// oauth.ErrRefreshTokenNotFound for unknown / expired tokens (same oracle-
// resistant indistinguishability as Consume).
func (m *MemoryRefreshTokenStore) Inspect(_ context.Context, token string) (*oauth.RefreshToken, error) {
	m.mu.Lock()
	entry, ok := m.entries[token]
	m.mu.Unlock()
	if !ok {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	if entry.IsExpired() {
		// Lazy GC of expired entries — keeps the map from
		// accumulating stale keys without a sweeper goroutine.
		m.mu.Lock()
		delete(m.entries, token)
		m.mu.Unlock()
		return nil, oauth.ErrRefreshTokenNotFound
	}
	return entry, nil
}

// Delete removes a token without going through Consume's rotation
// path. Idempotent per RFC 7009 §2.2 — deleting an unknown token
// returns nil. Also wipes the families-map marker so an explicit
// /token/revoke can't subsequently mis-trigger a reuse-detection
// signal on the same token.
func (m *MemoryRefreshTokenStore) Delete(_ context.Context, token string) error {
	m.mu.Lock()
	delete(m.entries, token)
	delete(m.families, token)
	m.mu.Unlock()
	return nil
}

// DeleteAllForSubject removes every refresh token whose UserID +
// ClientID match. Implements [oauth.RefreshTokenSubjectIndex] so the
// "logout everywhere" endpoint can kill all refresh tokens for a
// (user, client) pair in one call. Returns the count of deletions.
//
// Wipes the families bookkeeping for every removed entry so a future
// presentation of any of those tokens looks like a vanilla
// invalid_grant rather than a stale reuse-detection event.
func (m *MemoryRefreshTokenStore) DeleteAllForSubject(_ context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int
	for tok, entry := range m.entries {
		if entry.UserID != userID {
			continue
		}
		// Empty clientID = no client filter (revoke across every client
		// the user has tokens for). Useful for admin "kill all sessions
		// for this user" actions.
		if clientID != "" && entry.ClientID != clientID {
			continue
		}
		delete(m.entries, tok)
		delete(m.families, tok)
		n++
	}
	return n, nil
}

// CountForSubject implements [oauth.RefreshTokenSubjectCounter] — counts
// the subject's tokens for clientID (or every client when clientID is
// empty) without deleting them, for erasure dry-run previews.
func (m *MemoryRefreshTokenStore) CountForSubject(_ context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int
	for _, entry := range m.entries {
		if entry.UserID != userID {
			continue
		}
		if clientID != "" && entry.ClientID != clientID {
			continue
		}
		n++
	}
	return n, nil
}

// GenerateRefreshToken mints a cryptographically random base64url-encoded
// token suitable for the OAuth 2.0 refresh_token grant. Exposed so
// custom oauth.RefreshTokenStore implementations can reuse it.
func GenerateRefreshToken() (string, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Compile-time interface checks.
var (
	_ oauth.RefreshTokenStore         = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenInspector     = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenSubjectIndex  = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenFamilyTracker = (*MemoryRefreshTokenStore)(nil)
)
