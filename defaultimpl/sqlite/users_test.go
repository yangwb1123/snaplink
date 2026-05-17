package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl/sqlite"
)

// newTestProvider builds an in-memory SQLite UserProvider for tests.
// Per-test isolation is automatic — :memory: gives each connection
// its own database. The provider closes when the test cleans up.
func newTestProvider(t *testing.T) *sqlite.UserProvider {
	t.Helper()
	// file::memory:?cache=shared so all connections in the pool see
	// the same in-memory DB (default :memory: opens a fresh DB per
	// connection, which makes table lookups race their own creation).
	p, err := sqlite.NewUserProvider("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("NewUserProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestUserProvider_CreateThenGetByID(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	in := &sso.User{
		ID:         "alice",
		ExternalID: "github:42",
		Provider:   "github",
		Email:      "alice@example.com",
		Name:       "Alice Example",
		Attributes: map[string]string{"team": "platform", "tier": "gold"},
	}
	if err := p.CreateOrUpdate(ctx, in); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	got, err := p.GetByID(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != in.ID || got.Email != in.Email || got.Name != in.Name {
		t.Errorf("user roundtrip mismatch: got %+v", got)
	}
	if got.Attributes["team"] != "platform" || got.Attributes["tier"] != "gold" {
		t.Errorf("attributes roundtrip mismatch: %v", got.Attributes)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not stamped: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
	}
}

func TestUserProvider_GetByID_MissingReturnsErrNoSuchUser(t *testing.T) {
	p := newTestProvider(t)
	_, err := p.GetByID(context.Background(), "ghost")
	if !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("missing GetByID err = %v, want ErrNoSuchUser", err)
	}
}

func TestUserProvider_GetByExternalID(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	_ = p.CreateOrUpdate(ctx, &sso.User{
		ID: "u1", ExternalID: "ext-1", Provider: "github",
	})
	_ = p.CreateOrUpdate(ctx, &sso.User{
		ID: "u2", ExternalID: "ext-2", Provider: "gitlab",
	})

	got, err := p.GetByExternalID(ctx, "github", "ext-1")
	if err != nil {
		t.Fatalf("GetByExternalID: %v", err)
	}
	if got.ID != "u1" {
		t.Errorf("got id %q, want u1", got.ID)
	}
}

func TestUserProvider_GetByExternalID_MissingReturnsErrNoSuchUser(t *testing.T) {
	p := newTestProvider(t)
	_, err := p.GetByExternalID(context.Background(), "github", "nope")
	if !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("got %v, want ErrNoSuchUser", err)
	}
}

func TestUserProvider_CreateOrUpdate_PreservesCreatedAt(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	first := &sso.User{ID: "alice", Email: "old@x"}
	if err := p.CreateOrUpdate(ctx, first); err != nil {
		t.Fatalf("first: %v", err)
	}
	createdAt := first.CreatedAt
	if createdAt.IsZero() {
		t.Fatal("CreatedAt not stamped on first insert")
	}

	// Wait a beat so UpdatedAt has a chance to move past CreatedAt
	// at unix-second resolution.
	time.Sleep(1100 * time.Millisecond)

	second := &sso.User{ID: "alice", Email: "new@x"}
	if err := p.CreateOrUpdate(ctx, second); err != nil {
		t.Fatalf("second: %v", err)
	}

	got, err := p.GetByID(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "new@x" {
		t.Errorf("update did not stick: email = %q", got.Email)
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt drifted on update: was %v, now %v", createdAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(createdAt) {
		t.Errorf("UpdatedAt did not advance: created=%v updated=%v", createdAt, got.UpdatedAt)
	}
}

func TestUserProvider_CreateOrUpdate_RejectsEmptyID(t *testing.T) {
	p := newTestProvider(t)
	err := p.CreateOrUpdate(context.Background(), &sso.User{})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestUserProvider_List_OrderById(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	for _, id := range []string{"z", "a", "m"} {
		_ = p.CreateOrUpdate(ctx, &sso.User{ID: id})
	}

	got, err := p.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d users, want 3", len(got))
	}
	want := []string{"a", "m", "z"}
	for i, u := range got {
		if u.ID != want[i] {
			t.Errorf("List[%d].ID = %q, want %q", i, u.ID, want[i])
		}
	}
}

func TestUserProvider_Delete_RemovesUser(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	_ = p.CreateOrUpdate(ctx, &sso.User{ID: "alice"})
	if err := p.Delete(ctx, "alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.GetByID(ctx, "alice"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("after delete GetByID err = %v, want ErrNoSuchUser", err)
	}
}

func TestUserProvider_Delete_MissingIDIsIdempotent(t *testing.T) {
	p := newTestProvider(t)
	if err := p.Delete(context.Background(), "ghost"); err != nil {
		t.Errorf("delete of missing id should be nil, got %v", err)
	}
}

func TestUserProvider_NilAttributes_RoundtripsAsNilOrEmpty(t *testing.T) {
	// A User created without Attributes should come back the same way
	// — no surprise allocation of an empty map.
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.CreateOrUpdate(ctx, &sso.User{ID: "u"})
	got, _ := p.GetByID(ctx, "u")
	if len(got.Attributes) != 0 {
		t.Errorf("nil attributes roundtrip = %v, want empty/nil", got.Attributes)
	}
}
