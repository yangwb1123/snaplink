package webauthn

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	_, err := NewHelper(Config{RPOrigins: []string{"https://example.com"}}, NewMemoryUserStore(), NewMemorySessionStore())
	if err == nil {
		t.Fatal("expected error when RPID missing")
	}
}

func TestNewHelper_RequiresAtLeastOneOrigin(t *testing.T) {
	_, err := NewHelper(Config{RPID: "example.com"}, NewMemoryUserStore(), NewMemorySessionStore())
	if err == nil {
		t.Fatal("expected error when RPOrigins empty")
	}
}

func TestNewHelper_RequiresStores(t *testing.T) {
	cfg := Config{RPID: "example.com", RPOrigins: []string{"https://sso.example.com"}}
	if _, err := NewHelper(cfg, nil, NewMemorySessionStore()); err == nil {
		t.Fatal("expected error when UserStore nil")
	}
	if _, err := NewHelper(cfg, NewMemoryUserStore(), nil); err == nil {
		t.Fatal("expected error when SessionStore nil")
	}
}

func TestNewHelper_DefaultSessionTTL(t *testing.T) {
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
	h := newHelperForTest(t)
	req := httptest.NewRequest("POST", "/webauthn/registration/finish", strings.NewReader("{}"))
	_, err := h.FinishRegistration(context.Background(), "ghost-session", req)
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

func TestBeginLogin_UnknownUserReturnsError(t *testing.T) {
	h := newHelperForTest(t)
	_, _, err := h.BeginLogin(context.Background(), "ghost@example.com")
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestFinishLogin_UnknownSessionReturnsError(t *testing.T) {
	h := newHelperForTest(t)
	req := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader("{}"))
	_, _, err := h.FinishLogin(context.Background(), "ghost-session", req)
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}

// ----- MemoryUserStore -----

func TestMemoryUserStore_CreateGetByNameAndHandle(t *testing.T) {
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
	store := NewMemoryUserStore()
	_, err := store.GetByName(context.Background(), "ghost")
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestMemoryUserStore_AddAndUpdateCredential(t *testing.T) {
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
	store := NewMemoryUserStore()
	err := store.AddCredential(context.Background(), "ghost", &gw.Credential{ID: []byte("x")})
	if !errors.Is(err, ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestMemoryUserStore_RemoveCredential(t *testing.T) {
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

func TestMemorySessionStore_TakeIsSingleUse(t *testing.T) {
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
	store := NewMemorySessionStore()
	_, err := store.Take(context.Background(), "ghost")
	if !errors.Is(err, ErrSessionUnknown) {
		t.Fatalf("got %v, want ErrSessionUnknown", err)
	}
}
