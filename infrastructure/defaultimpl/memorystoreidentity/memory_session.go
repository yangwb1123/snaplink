package memorystoreidentity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/core"
)

const sessionIDBytes = 32

// MemorySessionManager stores sessions in memory. Implements the full
// core.SessionManager including the admin extensions (ListByUser/ListAll).
type MemorySessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*core.Session
	ttl      time.Duration
}

func NewMemorySessionManager(ttl ...time.Duration) *MemorySessionManager {
	d := core.DefaultSessionDuration
	if len(ttl) > 0 {
		d = ttl[0]
	}
	return &MemorySessionManager{ttl: d, sessions: make(map[string]*core.Session)}
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
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
		TenantID:  meta.TenantID,
	}
	m.mu.Lock()
	m.sessions[id] = session
	m.mu.Unlock()
	return session, nil
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
		if s.UserID == userID {
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

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var (
	_ core.SessionManager     = (*MemorySessionManager)(nil)
	_ core.SessionMetaCreator = (*MemorySessionManager)(nil)
	_ core.SessionTenantIndex = (*MemorySessionManager)(nil)
)
