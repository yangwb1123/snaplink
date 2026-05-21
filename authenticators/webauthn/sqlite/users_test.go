package sqlite

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

func newUserStoreForTest(t *testing.T) *UserStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "users.db") + "?_journal=WAL&_busy_timeout=5000"
	store, err := NewUserStore(dsn)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestUserStore_CreateGetByNameAndHandle(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()

	user, err := store.CreateUser(ctx, "alice", "Alice Example")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if len(user.Handle) != 32 {
		t.Fatalf("Handle length = %d want 32", len(user.Handle))
	}

	got, err := store.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if got.Name != "alice" || got.DisplayName != "Alice Example" || !bytes.Equal(got.Handle, user.Handle) {
		t.Fatalf("GetByName mismatch: %#v", got)
	}

	byHandle, err := store.GetByHandle(ctx, user.Handle)
	if err != nil {
		t.Fatalf("GetByHandle: %v", err)
	}
	if byHandle.Name != "alice" {
		t.Fatalf("GetByHandle: got %q want alice", byHandle.Name)
	}
}

func TestUserStore_DuplicateCreateRejected(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()

	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := store.CreateUser(ctx, "alice", "Alice Again"); err == nil {
		t.Fatal("duplicate CreateUser must error")
	}
}

func TestUserStore_GetByNameUnknownReturnsSentinel(t *testing.T) {
	store := newUserStoreForTest(t)
	_, err := store.GetByName(context.Background(), "ghost")
	if !errors.Is(err, webauthn.ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestUserStore_GetByHandleUnknownReturnsSentinel(t *testing.T) {
	store := newUserStoreForTest(t)
	_, err := store.GetByHandle(context.Background(), []byte("ghost-handle"))
	if !errors.Is(err, webauthn.ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestUserStore_AddAndUpdateCredential(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cred := &gw.Credential{ID: []byte("cred-1"), PublicKey: []byte("pubkey-v1")}
	if err := store.AddCredential(ctx, "alice", cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}

	got, err := store.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByName after add: %v", err)
	}
	if len(got.Credentials) != 1 || !bytes.Equal(got.Credentials[0].PublicKey, []byte("pubkey-v1")) {
		t.Fatalf("credential not stored: %#v", got.Credentials)
	}

	cred.PublicKey = []byte("pubkey-v2")
	if err := store.UpdateCredential(ctx, "alice", cred); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}
	got, err = store.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByName after update: %v", err)
	}
	if !bytes.Equal(got.Credentials[0].PublicKey, []byte("pubkey-v2")) {
		t.Fatalf("UpdateCredential did not flow through: %#v", got.Credentials[0])
	}
}

func TestUserStore_AddCredentialUnknownUserErrors(t *testing.T) {
	store := newUserStoreForTest(t)
	err := store.AddCredential(context.Background(), "ghost", &gw.Credential{ID: []byte("x")})
	if !errors.Is(err, webauthn.ErrUserUnknown) {
		t.Fatalf("got %v, want ErrUserUnknown", err)
	}
}

func TestUserStore_UpdateUnknownCredentialErrors(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	err := store.UpdateCredential(ctx, "alice", &gw.Credential{ID: []byte("never-added")})
	if err == nil {
		t.Fatal("UpdateCredential against unknown credential must error")
	}
}

func TestUserStore_AddCredentialAppendsNotReplaces(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for _, id := range [][]byte{[]byte("c1"), []byte("c2"), []byte("c3")} {
		if err := store.AddCredential(ctx, "alice", &gw.Credential{ID: id, PublicKey: []byte("pk")}); err != nil {
			t.Fatalf("AddCredential %q: %v", id, err)
		}
	}
	got, _ := store.GetByName(ctx, "alice")
	if len(got.Credentials) != 3 {
		t.Fatalf("credentials length = %d want 3", len(got.Credentials))
	}
}

func TestUserStore_CrossInstanceSharing(t *testing.T) {
	// The whole multi-replica defense: a credential registered on
	// replica A is visible at login time on replica B against the
	// same DB file. Mirror PairwiseSubjectStore_CrossInstanceSharing.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_busy_timeout=5000"

	storeA, err := NewUserStore(dsn)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer storeA.Close()
	storeB, err := NewUserStore(dsn)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer storeB.Close()

	ctx := context.Background()
	user, err := storeA.CreateUser(ctx, "alice", "Alice")
	if err != nil {
		t.Fatalf("A.CreateUser: %v", err)
	}
	if err := storeA.AddCredential(ctx, "alice", &gw.Credential{ID: []byte("cred-A"), PublicKey: []byte("pk-A")}); err != nil {
		t.Fatalf("A.AddCredential: %v", err)
	}
	got, err := storeB.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("B.GetByName: %v", err)
	}
	if !bytes.Equal(got.Handle, user.Handle) {
		t.Fatal("cross-instance: handle mismatch")
	}
	if len(got.Credentials) != 1 || !bytes.Equal(got.Credentials[0].PublicKey, []byte("pk-A")) {
		t.Fatalf("cross-instance: credential not visible on B: %#v", got.Credentials)
	}
}
