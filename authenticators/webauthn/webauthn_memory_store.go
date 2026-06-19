package webauthn

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

// MemoryUserStore is an in-process [UserStore]. Suitable for tests +
// single-replica deployments. Production multi-replica setups MUST
// plug a shared store (SQLite, Postgres, etc.) so a credential
// registered on replica A is visible to replica B at login time.
type MemoryUserStore struct {
	mu     sync.RWMutex
	byName map[string]*User
}

// NewMemoryUserStore returns a ready-to-use empty store.
func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{byName: make(map[string]*User)}
}

// GetByName implements [UserStore].
func (m *MemoryUserStore) GetByName(_ context.Context, name string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.byName[name]
	if !ok {
		return nil, ErrUserUnknown
	}
	return u, nil
}

// GetByHandle returns the user with the given WebAuthn handle. Used
// by [Helper.FinishLogin] when the session encodes the handle
// rather than the username.
func (m *MemoryUserStore) GetByHandle(_ context.Context, handle []byte) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.byName {
		if bytesEqual(u.Handle, handle) {
			return u, nil
		}
	}
	return nil, ErrUserUnknown
}

// CreateUser implements [UserStore]. Generates a fresh 32-byte
// handle.
func (m *MemoryUserStore) CreateUser(_ context.Context, name, displayName string) (*User, error) {
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return nil, fmt.Errorf("webauthn: random handle: %w", err)
	}
	u := &User{
		Handle:      handle,
		Name:        name,
		DisplayName: displayName,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byName[name]; exists {
		return nil, errors.New("webauthn: user already exists")
	}
	m.byName[name] = u
	return u, nil
}

// AddCredential implements [UserStore].
func (m *MemoryUserStore) AddCredential(_ context.Context, name string, cred *gw.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[name]
	if !ok {
		return ErrUserUnknown
	}
	u.Credentials = append(u.Credentials, *cred)
	return nil
}

// UpdateCredential implements [UserStore].
func (m *MemoryUserStore) UpdateCredential(_ context.Context, name string, cred *gw.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[name]
	if !ok {
		return ErrUserUnknown
	}
	for i, c := range u.Credentials {
		if bytesEqual(c.ID, cred.ID) {
			u.Credentials[i] = *cred
			return nil
		}
	}
	return errors.New("webauthn: credential not found for user")
}

// RemoveCredential implements [UserStore]. Idempotent: a credentialID not
// enrolled for the user leaves the set unchanged (nil). Unknown user →
// ErrUserUnknown.
func (m *MemoryUserStore) RemoveCredential(_ context.Context, name string, credentialID []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[name]
	if !ok {
		return ErrUserUnknown
	}
	out := u.Credentials[:0:0]
	for _, c := range u.Credentials {
		if !bytesEqual(c.ID, credentialID) {
			out = append(out, c)
		}
	}
	u.Credentials = out
	return nil
}

// MemorySessionStore is an in-process [SessionStore]. Production
// multi-replica setups MUST plug a shared store — a session minted
// on replica A would otherwise be invisible to replica B at finish
// time.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionEntry
}

type sessionEntry struct {
	data      *gw.SessionData
	expiresAt time.Time
}

// NewMemorySessionStore returns a ready-to-use empty session store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: make(map[string]*sessionEntry)}
}

// Put implements [SessionStore].
func (m *MemorySessionStore) Put(_ context.Context, sessionID string, data *gw.SessionData, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[sessionID] = &sessionEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// Take implements [SessionStore]. Atomic remove-and-return so a
// session ID can be consumed at most once.
func (m *MemorySessionStore) Take(_ context.Context, sessionID string) (*gw.SessionData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	if !ok {
		return nil, ErrSessionUnknown
	}
	if time.Now().After(e.expiresAt) {
		return nil, ErrSessionExpired
	}
	return e.data, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
