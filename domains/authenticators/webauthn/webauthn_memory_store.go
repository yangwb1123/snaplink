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
	return cloneUser(u), nil
}

// GetByHandle returns the user with the given WebAuthn handle. Used
// by [Helper.FinishLogin] when the session encodes the handle
// rather than the username.
func (m *MemoryUserStore) GetByHandle(_ context.Context, handle []byte) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, u := range m.byName {
		if bytesEqual(u.Handle, handle) {
			return cloneUser(u), nil
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
		Handle:      append([]byte(nil), handle...),
		Name:        name,
		DisplayName: displayName,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byName[name]; exists {
		return nil, errors.New("webauthn: user already exists")
	}
	m.byName[name] = u
	return cloneUser(u), nil
}

// AddCredential implements [UserStore].
func (m *MemoryUserStore) AddCredential(_ context.Context, name string, cred *gw.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byName[name]
	if !ok {
		return ErrUserUnknown
	}
	u.Credentials = append(u.Credentials, cloneCredential(*cred))
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
			u.Credentials[i] = cloneCredential(*cred)
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
	u.CredentialExtensions[base64.RawURLEncoding.EncodeToString(credentialID)] = cloneExtensions(ext)
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
	out.Authenticator.AAGUID = append([]byte(nil), c.Authenticator.AAGUID...)
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

func cloneUser(u *User) *User {
	if u == nil {
		return nil
	}
	out := *u
	out.Handle = append([]byte(nil), u.Handle...)
	if u.Credentials != nil {
		out.Credentials = make([]gw.Credential, len(u.Credentials))
		for i, credential := range u.Credentials {
			out.Credentials[i] = cloneCredential(credential)
		}
	}
	if u.CredentialExtensions != nil {
		out.CredentialExtensions = make(map[string]CredentialExtensions, len(u.CredentialExtensions))
		for key, ext := range u.CredentialExtensions {
			out.CredentialExtensions[key] = cloneExtensions(ext)
		}
	}
	return &out
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
		data:      cloneSessionData(data),
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
	return cloneSessionData(e.data), nil
}

func cloneSessionData(data *gw.SessionData) *gw.SessionData {
	if data == nil {
		return nil
	}
	out := *data
	out.UserID = cloneSessionBytes(data.UserID)
	if data.AllowedCredentialIDs != nil {
		out.AllowedCredentialIDs = make([][]byte, len(data.AllowedCredentialIDs))
		for i, id := range data.AllowedCredentialIDs {
			out.AllowedCredentialIDs[i] = cloneSessionBytes(id)
		}
	}
	if data.Extensions != nil {
		out.Extensions = cloneSessionExtensions(data.Extensions)
	}
	if data.CredParams != nil {
		out.CredParams = make([]protocol.CredentialParameter, len(data.CredParams))
		copy(out.CredParams, data.CredParams)
	}
	return &out
}

func cloneSessionBytes(data []byte) []byte {
	if data == nil {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}

func cloneSessionExtensions(in protocol.AuthenticationExtensions) protocol.AuthenticationExtensions {
	if in == nil {
		return nil
	}
	out := make(protocol.AuthenticationExtensions, len(in))
	for key, value := range in {
		out[key] = cloneSessionExtensionValue(value)
	}
	return out
}

func cloneSessionExtensionValue(value any) any {
	switch v := value.(type) {
	case []byte:
		return cloneSessionBytes(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = cloneSessionExtensionValue(item)
		}
		return out
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out
	case map[string]any:
		return cloneSessionExtensionMap(v)
	case protocol.AuthenticationExtensions:
		return cloneSessionExtensions(v)
	case map[string]string:
		out := make(map[string]string, len(v))
		for key, item := range v {
			out[key] = item
		}
		return out
	case map[string]bool:
		out := make(map[string]bool, len(v))
		for key, item := range v {
			out[key] = item
		}
		return out
	default:
		return value
	}
}

func cloneSessionExtensionMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = cloneSessionExtensionValue(value)
	}
	return out
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
