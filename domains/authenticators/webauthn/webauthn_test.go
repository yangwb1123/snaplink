package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"
)

func newHelperForTest(t *testing.T) *Helper {
	t.Helper()
	h, err := NewHelper(Config{
		RPID:          "example.com",
		RPDisplayName: "Example AS",
		RPOrigins:     []string{"https://sso.example.com"},
		SessionTTL:    time.Minute,
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	return h
}

func TestNewHelper_RequiresRPID(t *testing.T) {
	t.Parallel()
	_, err := NewHelper(Config{RPOrigins: []string{"https://example.com"}}, NewMemoryUserStore(), NewMemorySessionStore())
	if err == nil {
		t.Fatal("expected error when RPID missing")
	}
}

func TestNewHelper_RequiresAtLeastOneOrigin(t *testing.T) {
	t.Parallel()
	_, err := NewHelper(Config{RPID: "example.com"}, NewMemoryUserStore(), NewMemorySessionStore())
	if err == nil {
		t.Fatal("expected error when RPOrigins empty")
	}
}

func TestNewHelper_RequiresStores(t *testing.T) {
	t.Parallel()
	cfg := Config{RPID: "example.com", RPOrigins: []string{"https://sso.example.com"}}
	if _, err := NewHelper(cfg, nil, NewMemorySessionStore()); err == nil {
		t.Fatal("expected error when UserStore nil")
	}
	if _, err := NewHelper(cfg, NewMemoryUserStore(), nil); err == nil {
		t.Fatal("expected error when SessionStore nil")
	}
}

func TestNewHelper_DefaultSessionTTL(t *testing.T) {
	t.Parallel()
	h, err := NewHelper(Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	if h.sessionTTL != 5*time.Minute {
		t.Fatalf("default ttl = %v, want 5m", h.sessionTTL)
	}
}

func TestBeginRegistration_CreatesUserAndReturnsOptions(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()

	creation, sessionID, err := h.BeginRegistration(ctx, "alice@example.com", "Alice Example")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if sessionID == "" {
		t.Fatal("sessionID empty")
	}
	if creation == nil || creation.Response.Challenge.String() == "" {
		t.Fatalf("creation options missing: %#v", creation)
	}
	if creation.Response.RelyingParty.ID != "example.com" {
		t.Fatalf("RP.ID = %q want example.com", creation.Response.RelyingParty.ID)
	}

	// User should now exist.
	user, err := h.users.GetByName(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if user.DisplayName != "Alice Example" {
		t.Fatalf("DisplayName = %q", user.DisplayName)
	}
	if len(user.Handle) != 32 {
		t.Fatalf("Handle length = %d want 32", len(user.Handle))
	}
}

func TestBeginRegistration_ReusesExistingUser(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()

	_, _, err := h.BeginRegistration(ctx, "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("first BeginRegistration: %v", err)
	}
	user1, _ := h.users.GetByName(ctx, "alice@example.com")

	_, _, err = h.BeginRegistration(ctx, "alice@example.com", "ignored on existing user")
	if err != nil {
		t.Fatalf("second BeginRegistration: %v", err)
	}
	user2, _ := h.users.GetByName(ctx, "alice@example.com")

	if !bytes.Equal(user1.Handle, user2.Handle) {
		t.Fatal("handle rotated on second BeginRegistration — must reuse existing user record")
	}
}

func TestFinishRegistration_UnknownSessionReturnsError(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	req := httptest.NewRequest("POST", "/webauthn/registration/finish", strings.NewReader("{}"))
	_, err := h.FinishRegistration(context.Background(), "ghost-session", "", req)
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

// TestFinishRegistration_UserMismatchRejected proves that when a valid session
// belongs to "alice" but the caller presents a bearer for "bob", FinishRegistration
// returns a mismatch error BEFORE any attestation is attempted. This guards against
// session hijacking where a valid bearer for user B drives a ceremony begun by user A.
func TestFinishRegistration_UserMismatchRejected(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()

	// Begin a registration for alice — this creates a live session.
	_, sessionID, err := h.BeginRegistration(ctx, "alice", "Alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	// Attempt to finish with a bearer for "bob" — must fail.
	req := httptest.NewRequest("POST", "/webauthn/registration/finish", strings.NewReader("{}"))
	_, err = h.FinishRegistration(ctx, sessionID, "bob", req)
	if err == nil {
		t.Fatal("expected error for user mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("error %q does not mention mismatch", err)
	}
}

func TestBeginLogin_UnknownUserReturnsError(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	_, _, err := h.BeginLogin(context.Background(), "ghost@example.com")
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestFinishLogin_UnknownSessionReturnsError(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader("{}"))
	_, _, err := h.FinishLogin(context.Background(), "ghost-session", req)
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

// ----- MemoryUserStore -----

func TestMemoryUserStore_CreateGetByNameAndHandle(t *testing.T) {
	t.Parallel()
	store := NewMemoryUserStore()
	ctx := context.Background()

	user, err := store.CreateUser(ctx, "alice", "Alice")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := store.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got != user {
		t.Fatal("GetByName did not return the created user")
	}

	gotByHandle, err := store.GetByHandle(ctx, user.Handle)
	if err != nil {
		t.Fatalf("GetByHandle: %v", err)
	}
	if gotByHandle != user {
		t.Fatal("GetByHandle did not return the created user")
	}
}

func TestMemoryUserStore_DuplicateCreateRejected(t *testing.T) {
	t.Parallel()
	store := NewMemoryUserStore()
	ctx := context.Background()

	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := store.CreateUser(ctx, "alice", "Alice Again"); err == nil {
		t.Fatal("duplicate CreateUser must error")
	}
}

func TestMemoryUserStore_GetByNameUnknownReturnsSentinel(t *testing.T) {
	t.Parallel()
	store := NewMemoryUserStore()
	_, err := store.GetByName(context.Background(), "ghost")
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestMemoryUserStore_AddAndUpdateCredential(t *testing.T) {
	t.Parallel()
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, "alice", "Alice")

	cred := &gw.Credential{ID: []byte("cred-1"), PublicKey: []byte("pubkey-v1")}
	if err := store.AddCredential(ctx, "alice", cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	got, _ := store.GetByName(ctx, "alice")
	if len(got.Credentials) != 1 || !bytes.Equal(got.Credentials[0].PublicKey, []byte("pubkey-v1")) {
		t.Fatalf("credential not stored: %#v", got.Credentials)
	}

	// Update — bump the PublicKey to verify the update reflows into storage.
	cred.PublicKey = []byte("pubkey-v2")
	if err := store.UpdateCredential(ctx, "alice", cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}
	got, _ = store.GetByName(ctx, "alice")
	if !bytes.Equal(got.Credentials[0].PublicKey, []byte("pubkey-v2")) {
		t.Fatalf("UpdateCredential did not flow through: %#v", got.Credentials[0])
	}
}

func TestMemoryUserStore_AddCredentialUnknownUserErrors(t *testing.T) {
	t.Parallel()
	store := NewMemoryUserStore()
	err := store.AddCredential(context.Background(), "ghost", &gw.Credential{ID: []byte("x")})
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestMemoryUserStore_RemoveCredential(t *testing.T) {
	t.Parallel()
	store := NewMemoryUserStore()
	ctx := context.Background()
	_, _ = store.CreateUser(ctx, "alice", "Alice")
	_ = store.AddCredential(ctx, "alice", &gw.Credential{ID: []byte("cred-1")})
	_ = store.AddCredential(ctx, "alice", &gw.Credential{ID: []byte("cred-2")})

	if err := store.RemoveCredential(ctx, "alice", []byte("cred-1")); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}
	got, _ := store.GetByName(ctx, "alice")
	if len(got.Credentials) != 1 || !bytes.Equal(got.Credentials[0].ID, []byte("cred-2")) {
		t.Fatalf("after remove = %#v, want only cred-2", got.Credentials)
	}

	// Idempotent: removing an absent credential is a no-op.
	if err := store.RemoveCredential(ctx, "alice", []byte("nope")); err != nil {
		t.Fatalf("RemoveCredential absent: %v", err)
	}
	if got, _ := store.GetByName(ctx, "alice"); len(got.Credentials) != 1 {
		t.Fatalf("absent remove changed the set: %#v", got.Credentials)
	}

	// Unknown user → sentinel.
	if err := store.RemoveCredential(ctx, "ghost", []byte("cred-2")); !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("unknown user got %v, want ErrUserUnknown", err)
	}
}

// ----- MemorySessionStore -----

func TestMemorySessionStore_PutThenTake(t *testing.T) {
	t.Parallel()
	store := NewMemorySessionStore()
	ctx := context.Background()
	want := &gw.SessionData{Challenge: "abc", UserID: []byte("alice")}

	if err := store.Put(ctx, "s1", want, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Take(ctx, "s1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Challenge != want.Challenge {
		t.Fatalf("challenge round-trip: got %q want %q", got.Challenge, want.Challenge)
	}
}

func TestMemorySessionStore_PutReclaimsAbandoned(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	store.sessions["stale"] = &sessionEntry{
		data:      &gw.SessionData{Challenge: "stale"},
		expiresAt: now.Add(-time.Hour),
	}
	store.sessions["live"] = &sessionEntry{
		data:      &gw.SessionData{Challenge: "live"},
		expiresAt: now.Add(time.Hour),
	}
	store.lastSweep.Store(0)

	if err := store.Put(context.Background(), "fresh", &gw.SessionData{Challenge: "fresh"}, time.Minute); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(store.sessions) != 2 {
		t.Fatalf("sessions after sweep = %d, want 2", len(store.sessions))
	}
	if _, ok := store.sessions["stale"]; ok {
		t.Error("abandoned expired session remains after Put sweep")
	}
	for _, id := range []string{"live", "fresh"} {
		if _, ok := store.sessions[id]; !ok {
			t.Errorf("session %q should be retained", id)
		}
	}
}

func TestMemorySessionStore_SweepKeepsExactBoundary(t *testing.T) {
	store := NewMemorySessionStore()
	now := time.Now()
	store.sessions["boundary"] = &sessionEntry{expiresAt: now}
	store.lastSweep.Store(now.Add(-webauthnSessionSweepInterval).UnixNano())
	store.mu.Lock()
	store.sweepExpiredLocked(now)
	store.mu.Unlock()
	if _, ok := store.sessions["boundary"]; !ok {
		t.Error("exact-boundary session was swept")
	}
}

func TestMemorySessionStore_TakeIsSingleUse(t *testing.T) {
	t.Parallel()
	store := NewMemorySessionStore()
	ctx := context.Background()
	_ = store.Put(ctx, "s1", &gw.SessionData{Challenge: "x"}, time.Minute)

	if _, err := store.Take(ctx, "s1"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	_, err := store.Take(ctx, "s1")
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("second Take: got %v want ErrSessionUnknown (single-use)", err)
	}
}

func TestMemorySessionStore_ExpiredSessionReturnsExpired(t *testing.T) {
	t.Parallel()
	store := NewMemorySessionStore()
	ctx := context.Background()
	_ = store.Put(ctx, "s1", &gw.SessionData{Challenge: "x"}, -1*time.Second)

	_, err := store.Take(ctx, "s1")
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("got %v, want ErrSessionExpired", err)
	}
	// And the entry should be gone — second Take returns Unknown.
	_, err = store.Take(ctx, "s1")
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("post-expired Take: got %v want ErrSessionUnknown", err)
	}
}

func TestMemorySessionStore_TakeUnknownReturnsSentinel(t *testing.T) {
	t.Parallel()
	store := NewMemorySessionStore()
	_, err := store.Take(context.Background(), "ghost")
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

// ----- BeginLoginConditional / FinishLoginConditional -----

func TestBeginLoginConditional_ReturnsOptionsWithMediation(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()

	assertion, sessionID, err := h.BeginLoginConditional(ctx)
	if err != nil {
		t.Fatalf("BeginLoginConditional: %v", err)
	}
	if sessionID == "" {
		t.Fatal("sessionID empty")
	}
	if assertion == nil {
		t.Fatal("assertion is nil")
	}
	if assertion.Response.Challenge.String() == "" {
		t.Fatal("challenge missing from assertion")
	}
	if assertion.Response.RelyingPartyID != "example.com" {
		t.Fatalf("RP.ID = %q want example.com", assertion.Response.RelyingPartyID)
	}
	// The mediation field MUST be set to "conditional".
	if assertion.Mediation != protocol.MediationConditional {
		t.Fatalf("Mediation = %q, want %q (conditional)", assertion.Mediation, protocol.MediationConditional)
	}
	// AllowedCredentials MUST be empty for discoverable/conditional login.
	if len(assertion.Response.AllowedCredentials) != 0 {
		t.Fatalf("AllowedCredentials = %v, want empty for discoverable login", assertion.Response.AllowedCredentials)
	}
}

func TestFinishLoginConditional_UnknownSessionReturnsError(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	req := httptest.NewRequest("POST", "/webauthn/login/conditional/finish", strings.NewReader("{}"))
	_, _, err := h.FinishLoginConditional(context.Background(), "ghost-session", req)
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

// nonHandleResolverStore wraps MemoryUserStore but does NOT expose
// handleResolver — used to verify FinishLoginConditional's guard.
type nonHandleResolverStore struct {
	inner *MemoryUserStore
}

func (s *nonHandleResolverStore) GetByName(ctx context.Context, name string) (*User, error) {
	return s.inner.GetByName(ctx, name)
}
func (s *nonHandleResolverStore) CreateUser(ctx context.Context, name, displayName string) (*User, error) {
	return s.inner.CreateUser(ctx, name, displayName)
}
func (s *nonHandleResolverStore) AddCredential(ctx context.Context, name string, cred *gw.Credential) error {
	return s.inner.AddCredential(ctx, name, cred)
}
func (s *nonHandleResolverStore) UpdateCredential(ctx context.Context, name string, cred *gw.Credential) error {
	return s.inner.UpdateCredential(ctx, name, cred)
}
func (s *nonHandleResolverStore) RemoveCredential(ctx context.Context, name string, credentialID []byte) error {
	return s.inner.RemoveCredential(ctx, name, credentialID)
}

func TestFinishLoginConditional_RequiresHandleResolver(t *testing.T) {
	t.Parallel()
	h, err := NewHelper(Config{
		RPID:       "example.com",
		RPOrigins:  []string{"https://sso.example.com"},
		SessionTTL: time.Minute,
	}, &nonHandleResolverStore{inner: NewMemoryUserStore()}, NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	ctx := context.Background()

	// Begin a conditional session.
	_, sessionID, err := h.BeginLoginConditional(ctx)
	if err != nil {
		t.Fatalf("BeginLoginConditional: %v", err)
	}

	req := httptest.NewRequest("POST", "/webauthn/login/conditional/finish", strings.NewReader("{}"))
	_, _, err = h.FinishLoginConditional(ctx, sessionID, req)
	if err == nil {
		t.Fatal("expected error for store without handleResolver, got nil")
	}
	if !strings.Contains(err.Error(), "handle resolution") {
		t.Fatalf("error %q does not mention handle resolution", err)
	}
}

// TestFinishLoginConditional_HappyPath validates a full conditional-mediation
// round trip: begin (discoverable, no username), sign the challenge with a
// software authenticator including the user's handle, and finish successfully.
// ----- credProps / largeBlob-support registration extensions -----

// TestBeginRegistration_NoExtensionsByDefault proves the byte-identical
// default: with neither Config.RequestCredProps nor
// Config.RequestLargeBlobSupport set, BeginRegistration sends no
// "extensions" key at all — the same wire shape as a pre-extension build.
func TestBeginRegistration_NoExtensionsByDefault(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	creation, _, err := h.BeginRegistration(context.Background(), "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(creation.Response.Extensions) != 0 {
		t.Fatalf("Extensions = %#v, want empty (byte-identical default)", creation.Response.Extensions)
	}
}

// TestBeginRegistration_RequestsCredPropsAndLargeBlobSupport proves both
// opt-in flags are threaded onto the creation options simultaneously —
// exercising that registrationExtensions builds ONE merged map (a second
// gw.WithExtensions call would silently overwrite the first, per
// go-webauthn's WithExtensions implementation).
func TestBeginRegistration_RequestsCredPropsAndLargeBlobSupport(t *testing.T) {
	t.Parallel()
	h, err := NewHelper(Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example AS",
		RPOrigins:               []string{"https://sso.example.com"},
		RequestCredProps:        true,
		RequestLargeBlobSupport: true,
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	creation, _, err := h.BeginRegistration(context.Background(), "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if got, ok := creation.Response.Extensions[extensionCredProps].(bool); !ok || !got {
		t.Fatalf("Extensions[credProps] = %#v, want true", creation.Response.Extensions[extensionCredProps])
	}
	lb, ok := creation.Response.Extensions[extensionLargeBlob].(map[string]any)
	if !ok || lb["support"] != "preferred" {
		t.Fatalf("Extensions[largeBlob] = %#v, want {support: preferred}", creation.Response.Extensions[extensionLargeBlob])
	}
}

// TestExtensionsFromCreation_CredPropsRK proves the pure parsing logic maps
// a credProps "rk" output to Discoverable, distinguishing true, false, and
// absent (nil, not false) — go-webauthn has no typed credProps support (as
// of v0.17.x it's a bare map[string]any), so this is the only place that
// shape is interpreted.
func TestExtensionsFromCreation_CredPropsRK(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		results protocol.AuthenticationExtensionsClientOutputs
		want    *bool
	}{
		{"rk true", protocol.AuthenticationExtensionsClientOutputs{extensionCredProps: map[string]any{"rk": true}}, boolPtr(true)},
		{"rk false", protocol.AuthenticationExtensionsClientOutputs{extensionCredProps: map[string]any{"rk": false}}, boolPtr(false)},
		{"credProps absent", protocol.AuthenticationExtensionsClientOutputs{}, nil},
		{"credProps malformed (not a map)", protocol.AuthenticationExtensionsClientOutputs{extensionCredProps: "oops"}, nil},
		{"rk missing from credProps", protocol.AuthenticationExtensionsClientOutputs{extensionCredProps: map[string]any{}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extensionsFromCreation(tc.results).Discoverable
			assertBoolPtrEqual(t, got, tc.want)
		})
	}
}

// TestExtensionsFromCreation_LargeBlobSupported mirrors the credProps test
// for the largeBlob registration-time "supported" detection output.
func TestExtensionsFromCreation_LargeBlobSupported(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		results protocol.AuthenticationExtensionsClientOutputs
		want    *bool
	}{
		{"supported true", protocol.AuthenticationExtensionsClientOutputs{extensionLargeBlob: map[string]any{"supported": true}}, boolPtr(true)},
		{"supported false", protocol.AuthenticationExtensionsClientOutputs{extensionLargeBlob: map[string]any{"supported": false}}, boolPtr(false)},
		{"largeBlob absent", protocol.AuthenticationExtensionsClientOutputs{}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extensionsFromCreation(tc.results).LargeBlobSupported
			assertBoolPtrEqual(t, got, tc.want)
		})
	}
}

// TestPersistCredentialExtensions_NoopWhenNothingCaptured proves that when
// ext is the zero value (neither flag requested / nothing echoed),
// persistCredentialExtensions never calls into the store — verified via a
// store whose SetCredentialExtensions would fail the test if invoked.
func TestPersistCredentialExtensions_NoopWhenNothingCaptured(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	store := &failIfCalledExtensionStore{MemoryUserStore: NewMemoryUserStore(), t: t}
	h.users = store
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	h.persistCredentialExtensions(ctx, "alice", []byte("cred-1"), CredentialExtensions{})
}

// TestPersistCredentialExtensions_StoreWithoutCapabilityIsNoop proves a
// UserStore that does NOT implement credentialExtensionSetter is silently
// skipped — Discoverable/LargeBlobSupported simply never persist for that
// backend, matching the same-safe-as-unrequested convention.
func TestPersistCredentialExtensions_StoreWithoutCapabilityIsNoop(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	store := &nonHandleResolverStore{inner: NewMemoryUserStore()}
	h.users = store
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	rk := true
	// Must not panic — nonHandleResolverStore has no SetCredentialExtensions.
	h.persistCredentialExtensions(ctx, "alice", []byte("cred-1"), CredentialExtensions{Discoverable: &rk})
}

// TestPersistCredentialExtensions_PersistsToMemoryStore is the positive
// case: MemoryUserStore implements credentialExtensionSetter, and the
// captured extension flows into User.CredentialExtensions keyed by
// base64url(credentialID) — the same key MFAEnrollmentAdapter reads.
func TestPersistCredentialExtensions_PersistsToMemoryStore(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()
	if _, err := h.users.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	rk := true
	h.persistCredentialExtensions(ctx, "alice", []byte("cred-1"), CredentialExtensions{Discoverable: &rk})

	user, err := h.users.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	key := base64.RawURLEncoding.EncodeToString([]byte("cred-1"))
	got, ok := user.CredentialExtensions[key]
	if !ok || got.Discoverable == nil || !*got.Discoverable {
		t.Fatalf("CredentialExtensions[%q] = %#v, want Discoverable=true", key, got)
	}
}

// FinishRegistration_CapturesCredProps cannot be exercised via a full
// ceremony round trip: this package's test harness (softwareAuthenticator)
// deliberately avoids building a real CBOR attestation object — see
// TestFinishRegistrationGate's doc comment — so the credProps/largeBlob
// capture at FinishRegistration is proven at the [extensionsFromCreation]
// unit-test level above instead (the only seam between the parsed response
// and this package's stored fields).

// failIfCalledExtensionStore wraps MemoryUserStore but fails the test if
// SetCredentialExtensions is ever invoked — used to prove
// persistCredentialExtensions's early return on a zero-value ext.
type failIfCalledExtensionStore struct {
	*MemoryUserStore
	t *testing.T
}

func (s *failIfCalledExtensionStore) SetCredentialExtensions(ctx context.Context, name string, credentialID []byte, ext CredentialExtensions) error {
	s.t.Fatal("SetCredentialExtensions called for a zero-value ext — persistCredentialExtensions must no-op")
	return nil
}

func boolPtr(b bool) *bool { return &b }

func assertBoolPtrEqual(t *testing.T, got, want *bool) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Fatalf("got %v, want nil", *got)
	case want != nil && got == nil:
		t.Fatalf("got nil, want %v", *want)
	case want != nil && got != nil && *want != *got:
		t.Fatalf("got %v, want %v", *got, *want)
	}
}

func TestFinishLoginConditional_HappyPath(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()
	auth := newSoftwareAuthenticator(t)

	// Step 1: create a user + enroll a credential.
	user, err := h.users.CreateUser(ctx, "conditional-user", "Conditional User")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := h.users.AddCredential(ctx, "conditional-user", auth.credential(t, 1)); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	// Step 2: begin conditional mediation (no username).
	assertion, sessionID, err := h.BeginLoginConditional(ctx)
	if err != nil {
		t.Fatalf("BeginLoginConditional: %v", err)
	}
	if assertion.Mediation != protocol.MediationConditional {
		t.Fatalf("Mediation = %q, want %q", assertion.Mediation, protocol.MediationConditional)
	}
	if assertion.Response.AllowedCredentials != nil && len(assertion.Response.AllowedCredentials) > 0 {
		t.Fatal("discoverable session must have empty AllowedCredentials")
	}

	// Peek at the stored session to get the challenge.
	store := h.sessions.(*MemorySessionStore)
	store.mu.Lock()
	var storedChallenge string
	for _, e := range store.sessions {
		storedChallenge = e.data.Challenge
		break
	}
	store.mu.Unlock()
	if storedChallenge == "" {
		t.Fatal("no session challenge found")
	}

	// Step 3: sign the challenge with the authenticator, including the
	// user's handle (required for discoverable login).
	body := auth.assertJSON(t, testRPID, testOrigin, storedChallenge, 2, true, user.Handle)
	req := httptest.NewRequest("POST", "/webauthn/login/conditional/finish", strings.NewReader(body))

	// Step 4: finish conditional login.
	gotUser, cred, err := h.FinishLoginConditional(ctx, sessionID, req)
	if err != nil {
		t.Fatalf("FinishLoginConditional: %v", err)
	}
	if gotUser.Name != "conditional-user" {
		t.Fatalf("user = %q, want %q", gotUser.Name, "conditional-user")
	}
	if cred.Authenticator.SignCount != 2 {
		t.Fatalf("SignCount = %d, want 2 (advanced)", cred.Authenticator.SignCount)
	}
	if cred.Authenticator.CloneWarning {
		t.Fatal("CloneWarning set on a valid advancing-counter assertion")
	}
}
