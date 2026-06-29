package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

func newMFAProviderForTest(t *testing.T) (*WebAuthnMFAProvider, *Helper) {
	t.Helper()
	h := newHelperForTest(t)
	p, err := NewWebAuthnMFAProvider(h)
	if err != nil {
		t.Fatalf("NewWebAuthnMFAProvider: %v", err)
	}
	return p, h
}

// enrollUser seeds a user with a placeholder credential so BeginLogin
// can issue an assertion (without a Credential, the WebAuthn library
// rejects with "user has no credentials"). The credential ID + key
// are zero-byte placeholders — real authenticators produce them
// during navigator.credentials.create; tests only need the slot
// occupied so BeginLogin completes.
func enrollUser(t *testing.T, h *Helper, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.users.CreateUser(ctx, name, name); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	cred := &gw.Credential{
		ID:        []byte("test-credential-id"),
		PublicKey: []byte{0x01, 0x02, 0x03},
	}
	if err := h.users.AddCredential(ctx, name, cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
}

func TestNewWebAuthnMFAProvider_RejectsNilHelper(t *testing.T) {
	t.Parallel()
	if _, err := NewWebAuthnMFAProvider(nil); err == nil {
		t.Fatal("want error on nil helper")
	}
}

func TestWebAuthnMFAProvider_SupportedMethods(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	methods := p.SupportedMethods()
	if len(methods) != 1 || methods[0] != MethodWebAuthn {
		t.Fatalf("SupportedMethods = %v, want [webauthn]", methods)
	}
}

func TestWebAuthnMFAProvider_BeginRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	_, err := p.Begin(context.Background(), "alice", "totp")
	if !errors.Is(err, ErrWebAuthnMFAUnsupportedMethod) {
		t.Fatalf("got %v, want ErrWebAuthnMFAUnsupportedMethod", err)
	}
}

func TestWebAuthnMFAProvider_BeginRejectsEmptySubject(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	_, err := p.Begin(context.Background(), "", MethodWebAuthn)
	if !errors.Is(err, ErrWebAuthnMFAMissingSubject) {
		t.Fatalf("got %v, want ErrWebAuthnMFAMissingSubject", err)
	}
}

func TestWebAuthnMFAProvider_BeginUnknownUserSurfacesHelperError(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	_, err := p.Begin(context.Background(), "ghost@example.com", MethodWebAuthn)
	if err == nil {
		t.Fatal("want error for unknown user")
	}
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want wrapped ErrUserUnknown", err)
	}
}

func TestWebAuthnMFAProvider_BeginEnrolledUserReturnsOptionsAndSession(t *testing.T) {
	t.Parallel()
	p, h := newMFAProviderForTest(t)
	enrollUser(t, h, "alice@example.com")

	data, err := p.Begin(context.Background(), "alice@example.com", MethodWebAuthn)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if data["session"] == "" {
		t.Errorf("session id empty: %v", data)
	}
	if data["options"] == "" {
		t.Errorf("options blob empty: %v", data)
	}
	// Options should round-trip as JSON describing a CredentialAssertion.
	var assertion map[string]any
	if err := json.Unmarshal([]byte(data["options"]), &assertion); err != nil {
		t.Fatalf("options not valid JSON: %v", err)
	}
	publicKey, _ := assertion["publicKey"].(map[string]any)
	if publicKey == nil {
		t.Fatalf("options.publicKey missing: %v", assertion)
	}
	if _, ok := publicKey["challenge"]; !ok {
		t.Errorf("publicKey.challenge missing — Begin produced malformed assertion options: %v", publicKey)
	}
}

func TestWebAuthnMFAProvider_VerifyRejectsUnsupportedMethod(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	err := p.Verify(context.Background(), "alice", "totp", map[string]string{
		"session":   "sess",
		"assertion": "{}",
	})
	if !errors.Is(err, ErrWebAuthnMFAUnsupportedMethod) {
		t.Fatalf("got %v, want ErrWebAuthnMFAUnsupportedMethod", err)
	}
}

func TestWebAuthnMFAProvider_VerifyRejectsEmptySubject(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	err := p.Verify(context.Background(), "", MethodWebAuthn, map[string]string{
		"session":   "sess",
		"assertion": "{}",
	})
	if !errors.Is(err, ErrWebAuthnMFAMissingSubject) {
		t.Fatalf("got %v, want ErrWebAuthnMFAMissingSubject", err)
	}
}

func TestWebAuthnMFAProvider_VerifyRejectsMissingSession(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	err := p.Verify(context.Background(), "alice", MethodWebAuthn, map[string]string{
		"assertion": "{}",
	})
	if !errors.Is(err, ErrWebAuthnMFAMissingSession) {
		t.Fatalf("got %v, want ErrWebAuthnMFAMissingSession", err)
	}
}

func TestWebAuthnMFAProvider_VerifyRejectsMissingAssertion(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	err := p.Verify(context.Background(), "alice", MethodWebAuthn, map[string]string{
		"session": "sess",
	})
	if !errors.Is(err, ErrWebAuthnMFAMissingAssertion) {
		t.Fatalf("got %v, want ErrWebAuthnMFAMissingAssertion", err)
	}
}

func TestWebAuthnMFAProvider_VerifyUnknownSessionSurfacesHelperError(t *testing.T) {
	t.Parallel()
	p, _ := newMFAProviderForTest(t)
	err := p.Verify(context.Background(), "alice", MethodWebAuthn, map[string]string{
		"session":   "ghost-session",
		"assertion": "{}",
	})
	if err == nil {
		t.Fatal("want error for unknown session")
	}
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want wrapped ErrSessionUnknown", err)
	}
}

func TestWebAuthnMFAProvider_VerifyExpiredSessionSurfacesHelperError(t *testing.T) {
	t.Parallel()
	p, h := newMFAProviderForTest(t)
	enrollUser(t, h, "alice@example.com")

	// Inject an already-expired session directly. Negative TTL puts
	// expiresAt in the past, so Take returns ErrSessionExpired
	// before any subject resolution happens.
	now := time.Now()
	_ = h.sessions.Put(context.Background(), "expired-sess", &gw.SessionData{
		UserID:  []byte("ghost"),
		Expires: now.Add(-1 * time.Second),
	}, -time.Second)

	err := p.Verify(context.Background(), "alice@example.com", MethodWebAuthn, map[string]string{
		"session":   "expired-sess",
		"assertion": `{"id":"x","rawId":"x","type":"public-key","response":{}}`,
	})
	if err == nil {
		t.Fatal("want error for expired session")
	}
	// Acceptable: ErrSessionExpired OR ErrSessionUnknown (some
	// SessionStores prune on Take rather than report expired). Both
	// are confidentiality-equivalent at the wire (collapse to
	// mfa_invalid).
	if !errors.Is(err, ErrSessionExpired) && !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionExpired or ErrSessionUnknown", err)
	}
}
