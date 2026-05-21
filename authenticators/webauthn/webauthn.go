// Package webauthn provides WebAuthn (CTAP/FIDO2) registration +
// authentication helpers backed by github.com/go-webauthn/webauthn.
//
// The package intentionally does NOT implement [sso.Authenticator] —
// the standard Authenticator interface is single-step (credential
// in, result out), while WebAuthn requires a four-call ceremony:
//
//	register: client → server (begin)  → challenge + session
//	         server → client (finish) → attestation → store cred
//	login:    client → server (begin)  → challenge + session
//	         server → client (finish) → assertion → AuthResult
//
// Operators wire four HTTP handlers (one per Begin* / Finish*
// method) onto their router; the SDK keeps the begin/finish layer
// transport-agnostic so an embedder using gRPC or a custom
// protocol gets the same building blocks.
//
// Storage is pluggable via [UserStore] and [SessionStore]
// interfaces. Memory implementations ship for tests + single-
// replica deployments; production multi-replica deployments wire
// custom stores (the same SQLite / Redis / etcd backends used by
// the other distributed primitives in this codebase).
package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"
)

// User is the per-account WebAuthn state — handle + names +
// credentials registered against the account. Satisfies
// [gw.User] without re-exposing the third-party interface to
// SDK callers.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []gw.Credential
}

// WebAuthnID returns the user handle the authenticator binds
// credentials to.
func (u *User) WebAuthnID() []byte { return u.Handle }

// WebAuthnName returns the human-palatable username (e.g. the
// account email). Per WebAuthn §5.4.3 this is intended for display
// only — security decisions key off WebAuthnID.
func (u *User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the rendered name (e.g. "Alex Müller").
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }

// WebAuthnCredentials returns every credential the user has
// enrolled. The library uses this to filter `allowCredentials` on
// the next assertion challenge.
func (u *User) WebAuthnCredentials() []gw.Credential { return u.Credentials }

var _ gw.User = (*User)(nil)

// UserStore is the SPI for per-account WebAuthn state. GetByName
// returns [ErrUserUnknown] when the username is not enrolled;
// CreateUser mints a random Handle if the caller passes one
// empty.
type UserStore interface {
	GetByName(ctx context.Context, name string) (*User, error)
	CreateUser(ctx context.Context, name, displayName string) (*User, error)
	AddCredential(ctx context.Context, name string, cred *gw.Credential) error
	UpdateCredential(ctx context.Context, name string, cred *gw.Credential) error
}

// SessionStore holds challenge + session data between Begin* and
// Finish* calls. The session ID is opaque to the store; the helper
// mints it. Put MUST honor the TTL — expired sessions are
// invalid and the corresponding Finish* call MUST fail with
// [ErrSessionExpired]. Take returns + consumes a session atomically;
// repeat calls for the same sessionID after Take return
// [ErrSessionUnknown].
type SessionStore interface {
	Put(ctx context.Context, sessionID string, data *gw.SessionData, ttl time.Duration) error
	Take(ctx context.Context, sessionID string) (*gw.SessionData, error)
}

// ErrUserUnknown signals that no user with the supplied name is
// enrolled. UserStore implementations return this from GetByName
// when the username is not found.
var ErrUserUnknown = errors.New("webauthn: user unknown")

// ErrSessionUnknown signals that no session with the supplied ID
// exists — either the ID was never issued or it has already been
// consumed by a prior Take.
var ErrSessionUnknown = errors.New("webauthn: session unknown")

// ErrSessionExpired signals that the session existed but its TTL
// has elapsed. Returned from Take when an expired session is
// looked up.
var ErrSessionExpired = errors.New("webauthn: session expired")

// Helper bundles a configured [gw.WebAuthn] + the two stores. All
// four ceremony entry points (Begin/Finish × Register/Login) hang
// off this type.
type Helper struct {
	core       *gw.WebAuthn
	users      UserStore
	sessions   SessionStore
	sessionTTL time.Duration
}

// Config is the operator-supplied configuration. RPID is the
// Relying Party ID — should equal the registrable domain
// suffix of the origin the user-agent will report (e.g. "example.com"
// for an SSO server at sso.example.com). RPOrigins lists the
// allowed origins; production deployments MUST include the
// scheme (e.g. "https://sso.example.com").
type Config struct {
	RPID          string
	RPDisplayName string
	RPOrigins     []string
	SessionTTL    time.Duration
}

// NewHelper validates cfg + returns the helper. RPID + at least
// one RPOrigin are required.
func NewHelper(cfg Config, users UserStore, sessions SessionStore) (*Helper, error) {
	if cfg.RPID == "" {
		return nil, errors.New("webauthn: RPID required")
	}
	if len(cfg.RPOrigins) == 0 {
		return nil, errors.New("webauthn: at least one RPOrigin required")
	}
	if users == nil || sessions == nil {
		return nil, errors.New("webauthn: UserStore + SessionStore required")
	}
	core, err := gw.New(&gw.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: configure: %w", err)
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Helper{
		core:       core,
		users:      users,
		sessions:   sessions,
		sessionTTL: ttl,
	}, nil
}

// BeginRegistration starts a registration ceremony for name. When
// the user doesn't exist yet, a fresh record is created with the
// supplied displayName. Returns the CredentialCreation options the
// client passes to navigator.credentials.create + an opaque
// sessionID the client echoes back at FinishRegistration time.
func (h *Helper) BeginRegistration(ctx context.Context, name, displayName string) (*protocol.CredentialCreation, string, error) {
	user, err := h.users.GetByName(ctx, name)
	if errors.Is(err, ErrUserUnknown) {
		user, err = h.users.CreateUser(ctx, name, displayName)
	}
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: load user: %w", err)
	}
	creation, session, err := h.core.BeginRegistration(user)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin registration: %w", err)
	}
	sessionID, err := h.persistSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return creation, sessionID, nil
}

// FinishRegistration completes the ceremony. session is the ID
// returned by the matching BeginRegistration; r is the request
// carrying the attestation response in its body.
func (h *Helper) FinishRegistration(ctx context.Context, sessionID string, r *http.Request) (*gw.Credential, error) {
	session, err := h.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	user, err := h.userFromSession(ctx, session)
	if err != nil {
		return nil, err
	}
	cred, err := h.core.FinishRegistration(user, *session, r)
	if err != nil {
		return nil, fmt.Errorf("webauthn: finish registration: %w", err)
	}
	if err := h.users.AddCredential(ctx, user.Name, cred); err != nil {
		return nil, fmt.Errorf("webauthn: persist credential: %w", err)
	}
	return cred, nil
}

// BeginLogin starts an authentication ceremony for name. Returns
// the CredentialAssertion options + an opaque sessionID.
func (h *Helper) BeginLogin(ctx context.Context, name string) (*protocol.CredentialAssertion, string, error) {
	user, err := h.users.GetByName(ctx, name)
	if err != nil {
		return nil, "", err
	}
	assertion, session, err := h.core.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin login: %w", err)
	}
	sessionID, err := h.persistSession(ctx, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, sessionID, nil
}

// FinishLogin completes the authentication ceremony. The signed
// counter on the returned credential is updated in the user store
// so the next FinishLogin sees the new value — a replayed assertion
// (counter < stored counter) gets rejected by the library on the
// subsequent ceremony.
func (h *Helper) FinishLogin(ctx context.Context, sessionID string, r *http.Request) (*User, *gw.Credential, error) {
	session, err := h.sessions.Take(ctx, sessionID)
	if err != nil {
		return nil, nil, err
	}
	user, err := h.userFromSession(ctx, session)
	if err != nil {
		return nil, nil, err
	}
	cred, err := h.core.FinishLogin(user, *session, r)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: finish login: %w", err)
	}
	if err := h.users.UpdateCredential(ctx, user.Name, cred); err != nil {
		return nil, nil, fmt.Errorf("webauthn: persist updated credential: %w", err)
	}
	return user, cred, nil
}

func (h *Helper) persistSession(ctx context.Context, session *gw.SessionData) (string, error) {
	id, err := newSessionID()
	if err != nil {
		return "", fmt.Errorf("webauthn: random session id: %w", err)
	}
	if err := h.sessions.Put(ctx, id, session, h.sessionTTL); err != nil {
		return "", fmt.Errorf("webauthn: persist session: %w", err)
	}
	return id, nil
}

func (h *Helper) userFromSession(ctx context.Context, session *gw.SessionData) (*User, error) {
	user, err := h.users.GetByName(ctx, string(session.UserID))
	if err == nil {
		return user, nil
	}
	if !errors.Is(err, ErrUserUnknown) {
		return nil, err
	}
	// Fallback: the user ID inside the session is the raw user
	// handle. Walk every stored user looking for the matching
	// handle. Most stores would index by handle directly; this
	// fallback exists for the minimal MemoryUserStore.
	if walker, ok := h.users.(handleResolver); ok {
		return walker.GetByHandle(ctx, session.UserID)
	}
	return nil, err
}

type handleResolver interface {
	GetByHandle(ctx context.Context, handle []byte) (*User, error)
}

func newSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

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
