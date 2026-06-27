package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/snaplink/sso/domains/authenticators/webauthn"

	gw "github.com/go-webauthn/webauthn/webauthn"

	// Registers the "pgx" database/sql driver for the integration test ONLY.
	// Production code never imports pgx — NewUserStore receives the shared pool
	// the cmd builder already opened with this driver registered. The test must
	// open its own pool, so it self-registers the driver here. pgx/v5 is already
	// pinned in the module graph, so this adds no new require.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// openTestDB opens a pool against SSO_TEST_POSTGRES_DSN, dropping the table so
// each test starts clean, or skips when no DSN is configured (CI without a DB).
// SSO_TEST_POSTGRES_DSN e.g. postgres://user@localhost:5432/sso_test?sslmode=disable
// SSO_TEST_POSTGRES_DIALECT "cockroach" exercises the no-advisory-lock path.
func openTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres webauthn integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), "DROP TABLE IF EXISTS webauthn_users"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	return db, os.Getenv("SSO_TEST_POSTGRES_DIALECT") // "" => postgres
}

func newUserStoreForTest(t *testing.T) *UserStore {
	t.Helper()
	db, dialect := openTestDB(t)
	store, err := NewUserStore(db, dialect)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
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

func TestUserStore_RemoveCredential(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_ = store.AddCredential(ctx, "alice", &gw.Credential{ID: []byte("c1")})
	_ = store.AddCredential(ctx, "alice", &gw.Credential{ID: []byte("c2")})

	if err := store.RemoveCredential(ctx, "alice", []byte("c1")); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}
	got, _ := store.GetByName(ctx, "alice")
	if len(got.Credentials) != 1 || !bytes.Equal(got.Credentials[0].ID, []byte("c2")) {
		t.Fatalf("after remove = %#v, want only c2", got.Credentials)
	}

	// Idempotent: absent credential is a no-op.
	if err := store.RemoveCredential(ctx, "alice", []byte("nope")); err != nil {
		t.Fatalf("RemoveCredential absent: %v", err)
	}
	if got, _ := store.GetByName(ctx, "alice"); len(got.Credentials) != 1 {
		t.Fatalf("absent remove changed the set: %#v", got.Credentials)
	}

	// Unknown user -> sentinel.
	if err := store.RemoveCredential(ctx, "ghost", []byte("c2")); !errors.Is(err, webauthn.ErrUserUnknown) {
		t.Fatalf("unknown user got %v, want ErrUserUnknown", err)
	}
}

func TestUserStore_CredentialArrayRoundTrip(t *testing.T) {
	store := newUserStoreForTest(t)
	ctx := context.Background()
	if _, err := store.CreateUser(ctx, "alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	in := []*gw.Credential{
		{ID: []byte("id-1"), PublicKey: []byte("pk-1"), AttestationType: "none"},
		{ID: []byte("id-2"), PublicKey: []byte("pk-2"), AttestationType: "basic_full"},
	}
	for _, c := range in {
		if err := store.AddCredential(ctx, "alice", c); err != nil {
			t.Fatalf("AddCredential %x: %v", c.ID, err)
		}
	}
	got, err := store.GetByName(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	if len(got.Credentials) != 2 {
		t.Fatalf("round-trip length = %d want 2", len(got.Credentials))
	}
	if got.Credentials[1].AttestationType != "basic_full" || !bytes.Equal(got.Credentials[0].ID, []byte("id-1")) {
		t.Fatalf("round-trip lost fields: %#v", got.Credentials)
	}
}

// TestUserStore_CrossInstanceSharing is the HA defense: a credential registered
// through one pool is visible at login time through a SEPARATE pool to the same
// database, proving credentials are durable and cluster-shared (the parallel of
// the SQLite peer's cross-instance test, with two pools standing in for two
// replicas).
func TestUserStore_CrossInstanceSharing(t *testing.T) {
	dbA, dialect := openTestDB(t)
	storeA, err := NewUserStore(dbA, dialect)
	if err != nil {
		t.Fatalf("A: %v", err)
	}

	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	dbB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("B open: %v", err)
	}
	t.Cleanup(func() { _ = dbB.Close() })
	storeB, err := NewUserStore(dbB, dialect)
	if err != nil {
		t.Fatalf("B: %v", err)
	}

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
