package memorystoreoauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memreaper"
	"github.com/snaplink/sso/protocols/oauth"
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
	// MaxRotationsPerWindow + RotationWindow configure the OPTIONAL
	// per-family rotation-VELOCITY cap (oauth.RefreshTokenRotationLimiter).
	// Both must be positive for RecordRotation to ever report
	// windowExceeded — a non-positive cap or window leaves the limiter
	// inert (count is still returned, but the window is never "exceeded"),
	// so a store constructed without WithRefreshRotationLimit is
	// byte-identical to a build without the feature. Set them BEFORE the
	// store sees traffic (e.g. immediately after NewMemoryRefreshTokenStore);
	// they're exported to match MemoryAccountLockout's field-config style.
	MaxRotationsPerWindow int
	RotationWindow        time.Duration

	// MaxEntries (0 = unbounded, the default) caps the live `entries` map
	// size, checked at Issue time. StartReaper launches a background
	// sweep that removes an entry once its TTL elapses even when no
	// caller ever Consumes/Inspects that exact token again (the existing
	// lazy GC on those two paths only reaches a key someone looks up).
	// Neither changes behavior unless explicitly configured.
	//
	// The reaper deletes ONLY from `entries`, mirroring Inspect's own
	// lazy-GC scope exactly (see Inspect) — it never touches `families`,
	// so reuse detection for an already-rotated-away token is unaffected.
	// This is a pre-existing property of the store, not something the
	// reaper changes: presenting a token whose `entries` row is gone (by
	// either path) but whose `families` row is still present already
	// reads as a replay via Consume, reaper or not.
	MaxEntries int

	mu       sync.Mutex
	entries  map[string]*oauth.RefreshToken
	families map[string]string // token → familyID, KEPT after Consume for reuse detection
	// rotations is the per-family sliding-window rotation counter backing
	// RecordRotation. Pruned lazily on access (entries whose window start
	// is older than RotationWindow reset to a fresh count) so it can't grow
	// unbounded without a sweeper goroutine — the MemoryAccountLockout
	// discipline.
	rotations map[string]*rotationWindow
	reaper    *memreaper.Reaper
}

// rotationWindow is one family's fixed-window rotation counter:
// `count` rotations since `windowStart`. A rotation arriving after
// windowStart+RotationWindow rolls the window over to a fresh count of 1.
type rotationWindow struct {
	count       int
	windowStart time.Time
}

// NewMemoryRefreshTokenStore returns a ready-to-use store with no TTL
// of its own — TTLs are stamped per-oauth.RefreshToken at Issue time.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{
		entries:   make(map[string]*oauth.RefreshToken),
		families:  make(map[string]string),
		rotations: make(map[string]*rotationWindow),
	}
}

// StartReaper launches a background sweep of expired refresh tokens
// every interval. A non-positive interval is a no-op. Idempotent —
// calling it again stops the previous reaper first.
func (m *MemoryRefreshTokenStore) StartReaper(interval time.Duration) {
	_ = m.reaper.Close()
	m.reaper = memreaper.Start(interval, m.sweepExpired)
}

// Close stops the background reaper started via StartReaper, if any.
func (m *MemoryRefreshTokenStore) Close() error {
	return m.reaper.Close()
}

func (m *MemoryRefreshTokenStore) sweepExpired(time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for tok, entry := range m.entries {
		if entry.IsExpired() {
			delete(m.entries, tok)
		}
	}
}

func (m *MemoryRefreshTokenStore) Issue(_ context.Context, token string, info *oauth.RefreshToken) error {
	if token == "" || info == nil {
		return oauth.ErrRefreshTokenNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MaxEntries > 0 {
		if _, exists := m.entries[token]; !exists && len(m.entries) >= m.MaxEntries {
			return ErrStoreAtCapacity
		}
	}
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
		Amr:                  append([]string(nil), info.Amr...),
		Acr:                  info.Acr,
		AuthTime:             info.AuthTime,
		ConfirmationJKT:      info.ConfirmationJKT,
		Generation:           info.Generation,
		FamilyCreatedAt:      info.FamilyCreatedAt,
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
	// Drop the velocity counter — a revoked family can never rotate again,
	// so its window state is dead weight (and keeping it would let a
	// brand-new family that happened to reuse the (random) id inherit a
	// stale count).
	delete(m.rotations, familyID)
	return n, nil
}

// RecordRotation implements [oauth.RefreshTokenRotationLimiter]: it bumps
// familyID's fixed-window rotation counter and reports the post-increment
// count + whether the configured per-window cap was exceeded. Mirrors the
// MemoryAccountLockout sliding-window RMW: a rotation arriving after the
// window elapsed rolls over to a fresh count of 1.
//
// windowExceeded is only ever true when BOTH MaxRotationsPerWindow and
// RotationWindow are positive (the limiter is configured) AND the count
// crossed the cap. An empty familyID is a no-op (0, false, nil) — a
// family-untracked store can't velocity-limit. This impl never returns a
// non-nil error (in-memory), so the handler's fail-open path is only
// exercised by stores with real I/O.
func (m *MemoryRefreshTokenStore) RecordRotation(_ context.Context, familyID string) (int, bool, error) {
	if familyID == "" {
		return 0, false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	w, ok := m.rotations[familyID]
	if !ok {
		w = &rotationWindow{}
		m.rotations[familyID] = w
	}
	// Roll the fixed window over when it has elapsed. A non-positive
	// RotationWindow disables roll-over (the window never elapses), which
	// only matters when the limiter is unconfigured — and an unconfigured
	// limiter never reports windowExceeded anyway.
	if !w.windowStart.IsZero() && m.RotationWindow > 0 && now.Sub(w.windowStart) >= m.RotationWindow {
		w.count = 0
		w.windowStart = time.Time{}
	}
	w.count++
	if w.windowStart.IsZero() {
		w.windowStart = now
	}
	exceeded := m.MaxRotationsPerWindow > 0 && m.RotationWindow > 0 && w.count > m.MaxRotationsPerWindow
	return w.count, exceeded, nil
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

// DeleteAllForClient removes every refresh token bound to clientID,
// regardless of subject. Implements [oauth.RefreshTokenClientPurger] so a
// tenant suspension can purge every token issued to the tenant's clients in
// one pass. Returns the count of deletions.
//
// Wipes the families bookkeeping for every removed entry so a future
// presentation of any of those tokens looks like a vanilla invalid_grant
// rather than a stale reuse-detection event. Empty clientID is a no-op: a
// blank client is not a wildcard here (wiping every token in the store on an
// empty argument would be a footgun).
func (m *MemoryRefreshTokenStore) DeleteAllForClient(_ context.Context, clientID string) (int, error) {
	if clientID == "" {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int
	for tok, entry := range m.entries {
		if entry.ClientID != clientID {
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

// ListExpiring implements [oauth.RefreshTokenExpiryLister] — the expiry-
// calendar read backing the admin capacity-planning / pre-expiry-notification
// endpoint. Returns governance metadata ONLY (oauth.RefreshTokenThumbprint,
// never the raw token) for entries that are still ACTIVE (mirrors
// RefreshToken.IsExpired's boundary) and expire at or before `before`,
// soonest-first. limit <= 0 returns every matching entry — the admin handler
// is responsible for passing a bounded limit.
func (m *MemoryRefreshTokenStore) ListExpiring(_ context.Context, before time.Time, limit int) ([]oauth.RefreshTokenExpiry, error) {
	m.mu.Lock()
	out := make([]oauth.RefreshTokenExpiry, 0, len(m.entries))
	for tok, entry := range m.entries {
		if entry.IsExpired() || entry.ExpiresAt.After(before) {
			continue
		}
		out = append(out, oauth.RefreshTokenExpiry{
			Thumbprint: oauth.RefreshTokenThumbprint(tok),
			UserID:     entry.UserID,
			ClientID:   entry.ClientID,
			ExpiresAt:  entry.ExpiresAt,
		})
	}
	m.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if !out[i].ExpiresAt.Equal(out[j].ExpiresAt) {
			return out[i].ExpiresAt.Before(out[j].ExpiresAt)
		}
		return out[i].Thumbprint < out[j].Thumbprint
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
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
	_ oauth.RefreshTokenStore           = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenInspector       = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenSubjectIndex    = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenFamilyTracker   = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenClientPurger    = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenRotationLimiter = (*MemoryRefreshTokenStore)(nil)
	_ oauth.RefreshTokenExpiryLister    = (*MemoryRefreshTokenStore)(nil)
	_ io.Closer                         = (*MemoryRefreshTokenStore)(nil)
)
