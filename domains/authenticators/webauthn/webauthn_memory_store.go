package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
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
	return m.createUser(name, displayName, handle)
}

// CreateUserWithHandle implements the optional [HandlePreservingUserCreator]
// capability: creates the user with the caller-supplied handle (the snapshot
// restorer replays exported handles through it). The handle bytes are copied
// so post-call mutation cannot corrupt stored state.
func (m *MemoryUserStore) CreateUserWithHandle(_ context.Context, name, displayName string, handle []byte) (*User, error) {
	cp := make([]byte, len(handle))
	copy(cp, handle)
	return m.createUser(name, displayName, cp)
}

func (m *MemoryUserStore) createUser(name, displayName string, handle []byte) (*User, error) {
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

// SetCredentialExtensions implements the optional [CredentialExtensionSetter]
// capability: persists SDK-captured WebAuthn extension results (credProps /
// largeBlob-support) alongside the identified credential, keyed by
// base64url(credentialID) — the same encoding [MFAEnrollmentAdapter] uses
// for its factor IDs, so a listing lookup by that same key finds it.
func (m *MemoryUserStore) SetCredentialExtensions(_ context.Context, name string, credentialID []byte, ext CredentialExtensions) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[name]
	if !ok {
		return ErrUserUnknown
	}
	if u.CredentialExtensions == nil {
		u.CredentialExtensions = make(map[string]CredentialExtensions)
	}
	u.CredentialExtensions[base64.RawURLEncoding.EncodeToString(credentialID)] = ext
	return nil
}

// ListCredentials implements the optional [CredentialLister] capability:
// every user's credentials as export-local deep copies. The exported
// record's Attestation blob is zeroed (bulky, never read post-registration)
// while AttestationFormat is preserved (go-webauthn's GetAppID reads it at
// login). Credential and extension maps are copied, never aliased — a
// caller mutating an exported record cannot corrupt the live store.
func (m *MemoryUserStore) ListCredentials(_ context.Context) ([]UserCredentialRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]UserCredentialRecord, 0)
	for _, u := range m.byName {
		for _, c := range u.Credentials {
			rec := UserCredentialRecord{
				UserName:    u.Name,
				Handle:      append([]byte(nil), u.Handle...),
				DisplayName: u.DisplayName,
			}
			rec.Credential = cloneCredential(c)
			rec.Credential.Attestation = gw.CredentialAttestation{}
			rec.Extensions = cloneExtensions(u.CredentialExtensions[base64.RawURLEncoding.EncodeToString(c.ID)])
			out = append(out, rec)
		}
	}
	return out, nil
}

// cloneCredential deep-copies a gw.Credential so exported records never
// alias live store state. Only the byte slices and nested structs that
// exist in practice are copied; scalar fields copy by value.
func cloneCredential(c gw.Credential) gw.Credential {
	out := c
	out.ID = append([]byte(nil), c.ID...)
	out.PublicKey = append([]byte(nil), c.PublicKey...)
	out.Transport = append([]protocol.AuthenticatorTransport(nil), c.Transport...)
	out.Attestation = cloneAttestation(c.Attestation)
	return out
}

// cloneAttestation deep-copies the five attestation blob fields (the bulky
// ClientDataJSON / AuthenticatorData / Object bytes are the reason the
// exporter zeroes the whole blob after cloning — the copy never escapes
// ListCredentials).
func cloneAttestation(a gw.CredentialAttestation) gw.CredentialAttestation {
	a.ClientDataJSON = append([]byte(nil), a.ClientDataJSON...)
	a.ClientDataHash = append([]byte(nil), a.ClientDataHash...)
	a.AuthenticatorData = append([]byte(nil), a.AuthenticatorData...)
	a.Object = append([]byte(nil), a.Object...)
	return a
}

// cloneExtensions copies a CredentialExtensions value (bool pointers).
func cloneExtensions(ext CredentialExtensions) CredentialExtensions {
	if ext.Discoverable != nil {
		v := *ext.Discoverable
		ext.Discoverable = &v
	}
	if ext.LargeBlobSupported != nil {
		v := *ext.LargeBlobSupported
		ext.LargeBlobSupported = &v
	}
	return ext
}

var _ CredentialExtensionSetter = (*MemoryUserStore)(nil)

const webauthnSessionSweepInterval = time.Minute

// MemorySessionStore is an in-process [SessionStore]. Production
// multi-replica setups MUST plug a shared store — a session minted
// on replica A would otherwise be invisible to replica B at finish
// time.
type MemorySessionStore struct {
	mu        sync.Mutex
	sessions  map[string]*sessionEntry
	lastSweep atomic.Int64
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
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweepExpiredLocked(now)
	m.sessions[sessionID] = &sessionEntry{
		data:      data,
		expiresAt: now.Add(ttl),
	}
	return nil
}

// Take implements [SessionStore]. Atomic remove-and-return so a
// session ID can be consumed at most once.
func (m *MemorySessionStore) Take(_ context.Context, sessionID string) (*gw.SessionData, error) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sessions[sessionID]
	delete(m.sessions, sessionID)
	m.sweepExpiredLocked(now)
	if !ok {
		return nil, ErrSessionUnknown
	}
	if time.Since(e.expiresAt) > 0 {
		return nil, ErrSessionExpired
	}
	return e.data, nil
}

// sweepExpiredLocked bounds abandoned ceremony state without a background
// goroutine. The requested Take entry is removed before this runs, preserving
// ErrSessionExpired for an expired session that the caller actually presents.
func (m *MemorySessionStore) sweepExpiredLocked(now time.Time) {
	nowNanos := now.UnixNano()
	previous := m.lastSweep.Load()
	if nowNanos-previous < int64(webauthnSessionSweepInterval) ||
		!m.lastSweep.CompareAndSwap(previous, nowNanos) {
		return
	}
	for id, entry := range m.sessions {
		if entry.expiresAt.Before(now) {
			delete(m.sessions, id)
		}
	}
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
