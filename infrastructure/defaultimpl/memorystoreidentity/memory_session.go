package memorystoreidentity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/shared/core"
)

const sessionIDBytes = 32

// ErrStoreAtCapacity is returned by CreateWithMeta when MaxEntries is set
// and the store already holds that many sessions.
var ErrStoreAtCapacity = errors.New("memorystoreidentity: store at capacity")

// MemorySessionManager stores sessions in memory. Implements the full
// core.SessionManager including the admin extensions (ListByUser/ListAll).
//
// MaxEntries (0 = unbounded, the default) and StartReaper are optional: Get/
// ListByUser/ListByTenant already lazily skip an expired session on read,
// but a session nobody ever reads again after it expires (a captured login
// that's simply abandoned) has no such reader, so it would otherwise sit in
// the map forever. Neither changes behavior unless explicitly configured.
type MemorySessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*core.Session
	ttl      time.Duration

	MaxEntries int

	reaper *memreaper.Reaper
}

func NewMemorySessionManager(ttl ...time.Duration) *MemorySessionManager {
	d := core.DefaultSessionDuration
	if len(ttl) > 0 {
		d = ttl[0]
	}
	return &MemorySessionManager{ttl: d, sessions: make(map[string]*core.Session)}
}

// StartReaper launches a background sweep of expired sessions every
// interval. A non-positive interval is a no-op. Idempotent — calling it
// again stops the previous reaper first.
func (m *MemorySessionManager) StartReaper(interval time.Duration) {
	_ = m.reaper.Close()
	m.reaper = memreaper.Start(interval, func(time.Time) {
		m.mu.Lock()
		defer m.mu.Unlock()
		for id, s := range m.sessions {
			if s.IsExpired() {
				delete(m.sessions, id)
			}
		}
	})
}

// Close stops the background reaper started via StartReaper, if any.
func (m *MemorySessionManager) Close() error {
	return m.reaper.Close()
}

func (m *MemorySessionManager) Create(ctx context.Context, userID string) (*core.Session, error) {
	return m.CreateWithMeta(ctx, userID, core.SessionMeta{})
}

// CreateWithMeta implements core.SessionMetaCreator: it captures the device/
// location context (IP, user-agent) on the new session for the self-service
// session list.
func (m *MemorySessionManager) CreateWithMeta(_ context.Context, userID string, meta core.SessionMeta) (*core.Session, error) {
	id := randomHex(sessionIDBytes)
	now := time.Now()
	session := &core.Session{
		ID:               id,
		UserID:           userID,
		CreatedAt:        now,
		ExpiresAt:        now.Add(m.ttl),
		IP:               meta.IP,
		UserAgent:        meta.UserAgent,
		TenantID:         meta.TenantID,
		DeviceID:         meta.DeviceID,
		ClientID:         meta.ClientID,
		AuthorizedScopes: append([]string(nil), meta.AuthorizedScopes...),
		AuthTime:         meta.AuthTime,
		Kind:             meta.Kind,
		TrustScore:       meta.TrustScore,
		TrustSetAt:       meta.TrustSetAt,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.MaxEntries > 0 && len(m.sessions) >= m.MaxEntries {
		return nil, ErrStoreAtCapacity
	}
	m.sessions[id] = session
	return session, nil
}

// MarkStepUp implements core.SessionTrustManager: it flags the session for a
// step-up challenge on its next request. A missing session is not an error
// (it may have expired between the agent's List and this call — the flag would
// be moot anyway). Best-effort advisory state, never a hard deny.
func (m *MemorySessionManager) MarkStepUp(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.StepUpRequired = true
	}
	return nil
}

// SetTrust implements core.SessionTrustManager: it (re)binds the session's
// trust baseline. A missing session is a no-op (not an error).
func (m *MemorySessionManager) SetTrust(_ context.Context, sessionID string, score float64, setAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.TrustScore = score
		s.TrustSetAt = setAt
		// A fresh baseline supersedes a prior below-floor decision: clear the
		// flag so a re-verified session isn't perpetually challenged.
		s.StepUpRequired = false
	}
	return nil
}

func (m *MemorySessionManager) SetAuthorizedScopes(_ context.Context, sessionID string, scopes []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.AuthorizedScopes = append([]string(nil), scopes...)
	}
	return nil
}

func (m *MemorySessionManager) SetKind(_ context.Context, sessionID, kind string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if session, ok := m.sessions[sessionID]; ok {
		session.Kind = kind
	}
	return nil
}

// DeleteByTenant implements core.SessionTenantIndex: it removes every session
// stamped with tenantID, returning the count deleted. Backs proactive
// revocation on tenant suspension/deletion so a session minted while the
// tenant was Active can't outlive the suspension. Empty tenantID is a no-op
// (not a wildcard) — blanking the store on an empty argument would be a
// footgun.
func (m *MemorySessionManager) DeleteByTenant(_ context.Context, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int
	for id, s := range m.sessions {
		if s.TenantID == tenantID {
			delete(m.sessions, id)
			n++
		}
	}
	return n, nil
}

func (m *MemorySessionManager) Get(_ context.Context, sessionID string) (*core.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, core.ErrSessionNotFound
	}
	if s.Revoked || s.IsExpired() {
		return nil, core.ErrSessionNotFound
	}
	return s, nil
}

func (m *MemorySessionManager) Destroy(_ context.Context, sessionID string) error {
	m.mu.Lock()
	delete(m.sessions, sessionID)
	m.mu.Unlock()
	return nil
}

func (m *MemorySessionManager) Refresh(_ context.Context, sessionID string) (*core.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionID]
	if !ok {
		return nil, core.ErrSessionNotFound
	}
	// Refresh MUST NOT resurrect expired or revoked sessions —
	// otherwise a captured session id is valid forever to anyone
	// who can call Refresh (the SSO server doesn't expose Refresh
	// directly, but admin RPCs / embedders calling SessionManager
	// from their own handlers could trip this). Surface as
	// SessionNotFound so the failure shape matches what Get would
	// have returned.
	if s.Revoked || s.IsExpired() {
		return nil, core.ErrSessionNotFound
	}
	s.ExpiresAt = time.Now().Add(m.ttl)
	return s, nil
}

func (m *MemorySessionManager) ListByUser(_ context.Context, userID string) ([]*core.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.Session, 0)
	for _, s := range m.sessions {
		if s.UserID == userID && !s.Revoked && !s.IsExpired() {
			out = append(out, s)
		}
	}
	return out, nil
}

func (m *MemorySessionManager) ListAll(_ context.Context) ([]*core.Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out, nil
}

// ListPage implements core.PaginatedSessionLister: keyset pagination over a
// snapshot, sorted by ID. userID "" = every session (the ListAll fallback,
// including revoked/expired rows); non-empty = that user's ACTIVE sessions
// (the ListByUser fallback semantics). totalHint is the exact row count.
func (m *MemorySessionManager) ListPage(_ context.Context, userID string, q core.PageQuery) ([]*core.Session, []byte, int, error) {
	m.mu.RLock()
	sessions := make([]*core.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()
	var all []*core.Session
	if userID == "" {
		all = sessions
	} else {
		all = sessions[:0]
		for _, s := range sessions {
			if s.UserID == userID && !s.Revoked && !s.IsExpired() {
				all = append(all, s)
			}
		}
	}
	keyID := func(s *core.Session) (string, string) { return s.ID, s.ID }
	core.SortKeyset(all, q.Desc, keyID)
	return core.KeysetSlice(all, q, keyID)
}

// Compile-time interface check.
var _ core.PaginatedSessionLister = (*MemorySessionManager)(nil)

func (m *MemorySessionManager) TrackActivity(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[sessionID]; ok {
		s.LastActiveAt = time.Now()
	}
	return nil
}

// ListByTenant implements core.SessionTenantLister — returns every session
// stamped with tenantID (active or not). Empty tenantID returns empty list.
// A tenant-admin dashboard calls this to show sessions for their org.
func (m *MemorySessionManager) ListByTenant(_ context.Context, tenantID string) ([]*core.Session, error) {
	if tenantID == "" {
		return []*core.Session{}, nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*core.Session, 0)
	for _, s := range m.sessions {
		if s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	return out, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	_ core.SessionManager              = (*MemorySessionManager)(nil)
	_ core.SessionMetaCreator          = (*MemorySessionManager)(nil)
	_ core.SessionTenantIndex          = (*MemorySessionManager)(nil)
	_ core.SessionTenantLister         = (*MemorySessionManager)(nil)
	_ core.SessionTrustManager         = (*MemorySessionManager)(nil)
	_ core.SessionAuthorizationManager = (*MemorySessionManager)(nil)
	_ core.SessionKindManager          = (*MemorySessionManager)(nil)
	_ io.Closer                        = (*MemorySessionManager)(nil)
	_ core.SessionActivityTracker      = (*MemorySessionManager)(nil)
)
