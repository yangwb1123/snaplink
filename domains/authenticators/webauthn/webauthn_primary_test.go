package webauthn

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestNewWebAuthnPrimaryAuthenticator_RequiresHelper(t *testing.T) {
	t.Parallel()
	if _, err := NewWebAuthnPrimaryAuthenticator(nil); err == nil {
		t.Fatal("expected error for nil Helper, got nil")
	}
}

func TestWebAuthnPrimaryAuthenticator_NameAndLoginURL(t *testing.T) {
	t.Parallel()
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	if got := a.Name(); got != "webauthn" {
		t.Fatalf("Name() = %q, want %q", got, "webauthn")
	}
	if got := a.LoginURL("some-state"); got != "" {
		t.Fatalf("LoginURL() = %q, want empty (direct credential ceremony)", got)
	}
}

func TestWebAuthnPrimaryAuthenticator_LockoutIdentityAlwaysUnkeyable(t *testing.T) {
	t.Parallel()
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	cred := map[string]string{"session_id": "x", "assertion": "y"}
	if got := a.LockoutIdentity(cred); got != "" {
		t.Fatalf("LockoutIdentity() = %q, want empty (declared unkeyable)", got)
	}
}

func TestWebAuthnPrimaryAuthenticator_CallbackNotSupported(t *testing.T) {
	t.Parallel()
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	if _, err := a.Callback(context.Background(), &sso.CallbackState{}); err == nil {
		t.Fatal("expected callback-not-supported error, got nil")
	}
}

func TestWebAuthnPrimaryAuthenticator_Authenticate_MissingCredentialFields(t *testing.T) {
	t.Parallel()
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	cases := []map[string]string{
		{},
		{"session_id": "only-session"},
		{"assertion": "only-assertion"},
	}
	for _, cred := range cases {
		if _, err := a.Authenticate(context.Background(), &sso.AuthRequest{Credential: cred}); err == nil {
			t.Fatalf("Authenticate(%v): expected error, got nil", cred)
		}
	}
}

// TestWebAuthnPrimaryAuthenticator_Authenticate_UnknownSession verifies the
// anti-enumeration invariant: an unknown/expired ceremony session at the
// PRIMARY-login entry point must fold into the SAME oracle-safe signal
// (core.ErrCeremonySessionInvalid) the standalone WebAuthn ceremony endpoints
// collapse to 404 session_invalid — no new observable difference from
// reaching this state via /auth/login instead of /webauthn/login/*.
func TestWebAuthnPrimaryAuthenticator_Authenticate_UnknownSession(t *testing.T) {
	t.Parallel()
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	_, err = a.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"session_id": "ghost-session", "assertion": "{}"},
	})
	if err == nil {
		t.Fatal("expected error for unknown session, got nil")
	}
	if !errors.Is(err, core.ErrCeremonySessionInvalid) {
		t.Fatalf("error %v does not wrap core.ErrCeremonySessionInvalid", err)
	}
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("error %v does not wrap ErrSessionUnknown", err)
	}
}

// TestWebAuthnPrimaryAuthenticator_Authenticate_HappyPath validates a full
// passwordless-primary round trip: begin discoverable mediation (no
// username), sign the challenge with a software authenticator carrying the
// user's handle, then Authenticate resolves the identity and reports the
// webauthn AuthMethod — the SAME identity + credential resolution
// FinishLoginConditional performs for the standalone ceremony endpoint,
// now reachable through core.Authenticator.
func TestWebAuthnPrimaryAuthenticator_Authenticate_HappyPath(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()
	auth := newSoftwareAuthenticator(t)

	if _, err := h.users.CreateUser(ctx, "passkey-user", "Passkey User"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := h.users.AddCredential(ctx, "passkey-user", auth.credential(t, 1)); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	user, err := h.users.GetByName(ctx, "passkey-user")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}

	_, sessionID, err := h.BeginLoginConditional(ctx)
	if err != nil {
		t.Fatalf("BeginLoginConditional: %v", err)
	}

	store := h.sessions.(*MemorySessionStore)
	store.mu.Lock()
	var challenge string
	for _, e := range store.sessions {
		challenge = e.data.Challenge
		break
	}
	store.mu.Unlock()
	if challenge == "" {
		t.Fatal("no session challenge found")
	}

	body := auth.assertJSON(t, testRPID, testOrigin, challenge, 2, true, user.Handle)

	primary, err := NewWebAuthnPrimaryAuthenticator(h)
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	result, err := primary.Authenticate(ctx, &sso.AuthRequest{
		Provider:   "webauthn",
		Credential: map[string]string{"session_id": sessionID, "assertion": body},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.UserID != "passkey-user" {
		t.Fatalf("UserID = %q, want %q", result.UserID, "passkey-user")
	}
	if result.Provider != "webauthn" {
		t.Fatalf("Provider = %q, want %q", result.Provider, "webauthn")
	}
	if len(result.AuthMethods) != 1 || result.AuthMethods[0] != "webauthn" {
		t.Fatalf("AuthMethods = %v, want [webauthn]", result.AuthMethods)
	}
}

// TestWebAuthnPrimaryAuthenticator_Authenticate_BadAssertionNotCollapsedToSessionInvalid
// verifies a non-session ceremony failure (malformed assertion body) does
// NOT wrap core.ErrCeremonySessionInvalid — only unknown-session/unknown-user
// gets the 404 session_invalid treatment; a bad signature/parse failure falls
// through to the generic invalid_credentials bucket instead.
func TestWebAuthnPrimaryAuthenticator_Authenticate_BadAssertionNotCollapsedToSessionInvalid(t *testing.T) {
	t.Parallel()
	h := newHelperForTest(t)
	ctx := context.Background()
	if _, err := h.users.CreateUser(ctx, "passkey-user-2", "Passkey User 2"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, sessionID, err := h.BeginLoginConditional(ctx)
	if err != nil {
		t.Fatalf("BeginLoginConditional: %v", err)
	}
	primary, err := NewWebAuthnPrimaryAuthenticator(h)
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	_, err = primary.Authenticate(ctx, &sso.AuthRequest{
		Credential: map[string]string{"session_id": sessionID, "assertion": "not-json"},
	})
	if err == nil {
		t.Fatal("expected error for malformed assertion, got nil")
	}
	if errors.Is(err, core.ErrCeremonySessionInvalid) {
		t.Fatalf("malformed assertion must NOT collapse to ErrCeremonySessionInvalid, got %v", err)
	}
}

func TestWebAuthnPrimaryAuthenticator_InterfaceGuards(t *testing.T) {
	t.Parallel()
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	var _ sso.Authenticator = a
	var _ sso.LockoutKeyer = a
}

// TestWebAuthnPrimaryAuthenticator_WithLogger exercises the optional-logger
// wiring path (mirrors PasswordAuthenticator's WithPasswordLogger option) —
// a nil logger keeps the authenticator silent; a wired one must not change
// the returned error, only observe it.
func TestWebAuthnPrimaryAuthenticator_WithLogger(t *testing.T) {
	t.Parallel()
	var got []string
	logger := recordingLogger{record: func(msg string) { got = append(got, msg) }}
	a, err := NewWebAuthnPrimaryAuthenticator(newHelperForTest(t), WithWebAuthnPrimaryLogger(logger))
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	_, err = a.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"session_id": "ghost", "assertion": "{}"},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if len(got) == 0 {
		t.Fatal("expected logger to observe the ceremony failure")
	}
}

// recordingLogger is a minimal spi.Logger for asserting the optional logger
// hook fires — not a mock of business behavior, just an observation seam.
type recordingLogger struct {
	record func(msg string)
}

func (l recordingLogger) Info(msg string, _ ...any)  {}
func (l recordingLogger) Error(msg string, _ ...any) { l.record(msg) }
func (l recordingLogger) Debug(msg string, _ ...any) {}
