package wasmauth

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func newTestAuthenticator(t *testing.T, fixture string) *Authenticator {
	t.Helper()
	engine, err := NewEngine(context.Background(), loadFixture(t, fixture))
	if err != nil {
		t.Fatalf("NewEngine(%s): %v", fixture, err)
	}
	t.Cleanup(func() { _ = engine.Close(context.Background()) })
	a, err := New("wasm-test", engine)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestNewEngine_RejectsEmptyModule(t *testing.T) {
	t.Parallel()
	if _, err := NewEngine(context.Background(), nil); !errors.Is(err, ErrInvalidModule) {
		t.Errorf("err = %v, want ErrInvalidModule", err)
	}
}

func TestNewEngine_RejectsMissingExport(t *testing.T) {
	t.Parallel()
	if _, err := NewEngine(context.Background(), loadFixture(t, "missingexport.wasm")); !errors.Is(err, ErrInvalidModule) {
		t.Errorf("err = %v, want ErrInvalidModule", err)
	}
}

func TestNew_RequiresNameAndEngine(t *testing.T) {
	t.Parallel()
	engine, err := NewEngine(context.Background(), loadFixture(t, "policy.wasm"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer func() { _ = engine.Close(context.Background()) }()

	if _, err := New("", engine); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := New("x", nil); err == nil {
		t.Error("expected error for nil engine")
	}
}

func TestAuthenticator_CorrectCredentialSucceeds(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "policy.wasm")
	res, err := a.Authenticate(context.Background(), &core.AuthRequest{
		Credential: map[string]string{"username": "alice", "password": "correct-horse"},
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.UserID != "alice" || res.ExternalID != "alice" {
		t.Errorf("UserID/ExternalID = %q/%q, want alice/alice", res.UserID, res.ExternalID)
	}
	if res.Provider != "wasm-test" {
		t.Errorf("Provider = %q, want wasm-test", res.Provider)
	}
	if res.Attributes["role"] != "member" {
		t.Errorf("Attributes[role] = %q, want member", res.Attributes["role"])
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != "wasm-test" {
		t.Errorf("AuthMethods = %v, want [wasm-test]", res.AuthMethods)
	}
}

func TestAuthenticator_WrongCredentialRejected(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "policy.wasm")
	_, err := a.Authenticate(context.Background(), &core.AuthRequest{
		Credential: map[string]string{"username": "alice", "password": "wrong"},
	})
	if !errors.Is(err, errRejected) {
		t.Errorf("err = %v, want errRejected", err)
	}
}

func TestAuthenticator_UnknownUserRejected(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "policy.wasm")
	_, err := a.Authenticate(context.Background(), &core.AuthRequest{
		Credential: map[string]string{"username": "mallory", "password": "correct-horse"},
	})
	if !errors.Is(err, errRejected) {
		t.Errorf("err = %v, want errRejected", err)
	}
}

// TestAuthenticator_GuestTrapFailsClosed proves the fail-closed doctrine's
// most important case: a guest module that traps mid-evaluation must
// reject the login, never succeed or panic the host.
func TestAuthenticator_GuestTrapFailsClosed(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "trap.wasm")
	_, err := a.Authenticate(context.Background(), &core.AuthRequest{
		Credential: map[string]string{"username": "alice", "password": "correct-horse"},
	})
	if !errors.Is(err, errRejected) {
		t.Errorf("err = %v, want errRejected (guest trap must fail closed)", err)
	}
}

// TestAuthenticator_MalformedResponseFailsClosed proves a guest returning
// non-JSON garbage also rejects rather than crashing or (worse) somehow
// authenticating.
func TestAuthenticator_MalformedResponseFailsClosed(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "malformed.wasm")
	_, err := a.Authenticate(context.Background(), &core.AuthRequest{
		Credential: map[string]string{"username": "alice", "password": "correct-horse"},
	})
	if !errors.Is(err, errRejected) {
		t.Errorf("err = %v, want errRejected (malformed response must fail closed)", err)
	}
}

func TestAuthenticator_CallbackUnsupported(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "policy.wasm")
	if _, err := a.Callback(context.Background(), &core.CallbackState{}); err == nil {
		t.Error("expected Callback to be unsupported")
	}
	if u := a.LoginURL("state"); u != "" {
		t.Errorf("LoginURL = %q, want empty", u)
	}
}

func TestAuthenticator_Name(t *testing.T) {
	t.Parallel()
	a := newTestAuthenticator(t, "policy.wasm")
	if a.Name() != "wasm-test" {
		t.Errorf("Name() = %q, want wasm-test", a.Name())
	}
}

func TestEngine_CloseThenAuthenticateFailsClosed(t *testing.T) {
	t.Parallel()
	engine, err := NewEngine(context.Background(), loadFixture(t, "policy.wasm"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := engine.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	a, err := New("wasm-test", engine)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), &core.AuthRequest{
		Credential: map[string]string{"username": "alice", "password": "correct-horse"},
	}); err == nil {
		t.Error("expected an error after Close (fail-closed)")
	}
}

func TestEngine_CloseOnNilIsSafe(t *testing.T) {
	t.Parallel()
	var e *Engine
	if err := e.Close(context.Background()); err != nil {
		t.Errorf("Close on nil = %v, want nil", err)
	}
}
