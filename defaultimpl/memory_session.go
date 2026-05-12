package defaultimpl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

const sessionIDBytes = 32

// MemorySessionManager stores sessions in memory.
type MemorySessionManager struct {
	sessions sync.Map // sessionID -> *sso.Session
	ttl      time.Duration
}

func NewMemorySessionManager(ttl ...time.Duration) *MemorySessionManager {
	d := sso.DefaultSessionDuration
	if len(ttl) > 0 {
		d = ttl[0]
	}
	return &MemorySessionManager{ttl: d}
}

func (m *MemorySessionManager) Create(ctx context.Context, userID string) (*sso.Session, error) {
	id := randomHex(sessionIDBytes)
	now := time.Now()
	session := &sso.Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.ttl),
		Revoked:   false,
	}
	m.sessions.Store(id, session)
	return session, nil
}

func (m *MemorySessionManager) Get(ctx context.Context, sessionID string) (*sso.Session, error) {
	v, ok := m.sessions.Load(sessionID)
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	return v.(*sso.Session), nil
}

func (m *MemorySessionManager) Destroy(ctx context.Context, sessionID string) error {
	m.sessions.Delete(sessionID)
	return nil
}

func (m *MemorySessionManager) Refresh(ctx context.Context, sessionID string) (*sso.Session, error) {
	v, ok := m.sessions.Load(sessionID)
	if !ok {
		return nil, fmt.Errorf("session not found")
	}
	s := v.(*sso.Session)
	s.ExpiresAt = time.Now().Add(m.ttl)
	m.sessions.Store(sessionID, s)
	return s, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
