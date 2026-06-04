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
	"strings"
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

	// conveyance, when non-empty, is passed to BeginRegistration as
	// gw.WithConveyancePreference so the authenticator is asked to
	// produce an attestation statement ("direct"/"enterprise") or a
	// privacy-preserving one ("indirect"). Empty (the default) requests
	// no attestation — byte-identical to the pre-policy ceremony.
	conveyance protocol.ConveyancePreference

	// attestationPolicy gates the registered credential's AAGUID at
	// FinishRegistration AFTER go-webauthn verifies the attestation
	// statement. Nil / mode-off ⇒ no gating (byte-identical default).
	attestationPolicy *AttestationPolicy
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

	// AttestationConveyance sets the WebAuthn attestation conveyance
	// preference sent to the client at BeginRegistration. Accepts
	// ""/"none" (no attestation — the default, byte-identical to a
	// pre-policy build), "indirect", "direct", or "enterprise". A
	// non-none value asks the authenticator to convey an attestation
	// statement so the AAGUID it carries is attested (and, for "direct"/
	// "enterprise", the statement signature is verified by go-webauthn at
	// finish time). When an [AttestationPolicy] is active this MUST be
	// "direct" or "enterprise" — [NewHelper] FAILS otherwise, because under
	// none/indirect many authenticators omit the attestation statement and
	// report the zero AAGUID, which a denylist can never match (silent
	// bypass). Invalid values are rejected by [NewHelper].
	AttestationConveyance string

	// AttestationPolicy, when set to a gating mode, restricts which
	// authenticators may register by their AAGUID (allowlist / denylist),
	// applied at FinishRegistration. An active policy additionally rejects
	// any credential that conveyed no attestation (format "none") and
	// REQUIRES AttestationConveyance direct|enterprise. Nil ⇒ no gating (the
	// default — byte-identical to a pre-policy build).
	AttestationPolicy *AttestationPolicy
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
	conveyance, err := mapConveyance(cfg.AttestationConveyance)
	if err != nil {
		return nil, err
	}
	// Boot guard: an ACTIVE attestation policy is meaningless unless the RP
	// asks for attestation to be conveyed. Under conveyance ""/none/indirect
	// most authenticators omit the attestation statement and report the
	// all-zero AAGUID, which a denylist can never match (silent bypass) and an
	// allowlist gate can only reject wholesale — so a policy with weak
	// conveyance is silently ineffective. Require direct (or stronger:
	// enterprise) so the gate sees a verified, model-specific AAGUID. Fail
	// loud here rather than ship a dark policy. (mapConveyance has already
	// validated the string; "" / PreferIndirectAttestation are the
	// below-direct values.)
	if cfg.AttestationPolicy.Enabled() &&
		(conveyance == "" || conveyance == protocol.PreferIndirectAttestation) {
		return nil, fmt.Errorf(
			"webauthn: attestation policy mode %q requires AttestationConveyance \"direct\" or \"enterprise\" "+
				"(got %q) — an attestation policy on an un-attested AAGUID is meaningless",
			cfg.AttestationPolicy.Mode, conveyanceOrNone(cfg.AttestationConveyance))
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
		core:              core,
		users:             users,
		sessions:          sessions,
		sessionTTL:        ttl,
		conveyance:        conveyance,
		attestationPolicy: cfg.AttestationPolicy,
	}, nil
}

// mapConveyance validates + maps the operator-supplied conveyance string
// to the go-webauthn protocol constant. "" and "none" both map to the
// empty preference (no attestation requested — the default), so the
// BeginRegistration option is NOT passed and the wire is byte-identical to
// a pre-policy build. Any other unrecognized value is rejected so a typo
// in config fails loud at boot rather than silently disabling attestation.
func mapConveyance(s string) (protocol.ConveyancePreference, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		// Empty sentinel: BeginRegistration leaves Attestation at the
		// library default ("none") and does not apply the option.
		return "", nil
	case "indirect":
		return protocol.PreferIndirectAttestation, nil
	case "direct":
		return protocol.PreferDirectAttestation, nil
	case "enterprise":
		return protocol.PreferEnterpriseAttestation, nil
	default:
		return "", fmt.Errorf("webauthn: unknown attestation conveyance %q (want none|indirect|direct|enterprise)", s)
	}
}

// conveyanceOrNone renders the operator-supplied conveyance string for the
// boot-guard error message, normalizing the empty value to "none" so the
// error names a concrete preference the operator can recognize in config.
func conveyanceOrNone(s string) string {
	if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
		return v
	}
	return "none"
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
	var opts []gw.RegistrationOption
	if h.conveyance != "" {
		// Ask the client for an attestation statement so the AAGUID the
		// authenticator reports at finish time is attested. Only applied
		// when a non-none conveyance was configured — otherwise no option
		// is passed and the creation options are byte-identical to today.
		opts = append(opts, gw.WithConveyancePreference(h.conveyance))
	}
	creation, session, err := h.core.BeginRegistration(user, opts...)
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
	// Attestation-policy gate. Applied AFTER go-webauthn verified the
	// attestation statement (so cred.Authenticator.AAGUID is the
	// attestation-verified value) and BEFORE we persist — a denied
	// authenticator's credential is never written. Returns a typed
	// AttestationDeniedError carrying the canonical AAGUID so the wiring
	// layer can audit the denial precisely. Nil / mode-off ⇒ no gating.
	if err := h.checkAttestationPolicy(cred); err != nil {
		return nil, err
	}
	if err := h.users.AddCredential(ctx, user.Name, cred); err != nil {
		return nil, fmt.Errorf("webauthn: persist credential: %w", err)
	}
	return cred, nil
}

// AttestationPolicyEnabled reports whether this Helper has an active
// attestation policy (mode != off). The wiring layer uses it to decide
// whether to emit the registration audit events — keeping a Helper WITHOUT
// a policy byte-identical to a pre-policy build (no new audit on the
// success path). When the operator opts into a policy, the success +
// denial audit events become part of that feature.
func (h *Helper) AttestationPolicyEnabled() bool {
	return h.attestationPolicy.Enabled()
}

// checkAttestationPolicy applies the configured [AttestationPolicy] to a
// freshly-verified credential. Returns nil when no policy is configured
// (mode off) or the authenticator is permitted; otherwise an
// [AttestationDeniedError] carrying the canonical AAGUID + the policy mode +
// a machine-readable Reason. The canonical AAGUID is best-effort for the
// error/audit (an unparseable AAGUID yields "" but the denial still stands
// under allowlist).
//
// When a policy is ACTIVE the gate FIRST rejects a credential that conveyed
// NO attestation (format "none"). go-webauthn's VerifyAttestation accepts the
// "none" format with ZERO signature verification, so such a credential's
// AAGUID is the all-zero / unverifiable value: a denylist would never match
// it (a banned authenticator could downgrade to "none" and slip through) and
// an allowlist gate on an un-attested AAGUID is meaningless. Conveyance is
// only a PREFERENCE the client may ignore, so even an RP that asked for
// "direct" can receive a "none" credential — this is the structural fix that
// makes an active policy demand a verified attestation statement. The boot
// guard (requiring conveyance >= direct for an active policy) is the
// complementary half; together they close the downgrade bypass. Default-off
// (no policy) performs NO format check — byte-identical to a pre-policy build.
func (h *Helper) checkAttestationPolicy(cred *gw.Credential) error {
	if !h.attestationPolicy.Enabled() {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(cred.AttestationFormat), AttestationFormatNone) {
		return &AttestationDeniedError{
			AAGUID: CredentialAAGUID(cred.Authenticator.AAGUID),
			Mode:   h.attestationPolicy.Mode,
			Reason: ReasonAttestationFormatNone,
		}
	}
	if err := h.attestationPolicy.Check(cred.Authenticator.AAGUID); err != nil {
		canon, cerr := canonicalAAGUIDFromBytes(cred.Authenticator.AAGUID)
		if cerr != nil {
			canon = ""
		}
		return &AttestationDeniedError{AAGUID: canon, Mode: h.attestationPolicy.Mode, Reason: ReasonAAGUIDNotPermitted}
	}
	return nil
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
