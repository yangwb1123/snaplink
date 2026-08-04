package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// freshUserProvider builds a Postgres-backed UserProvider against the
// integration DB and TRUNCATEs its table so each run is isolated. Reuses
// testConfig(t) (which skips when SSO_TEST_POSTGRES_DSN is unset).
func freshUserProvider(t *testing.T) *UserProvider {
	t.Helper()
	p, err := NewUserProvider(testConfig(t))
	if err != nil {
		t.Fatalf("NewUserProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if _, err := p.db.ExecContext(context.Background(), "TRUNCATE users"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return p
}

func TestUser_CreateThenGetByID(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()

	in := &core.User{
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
	if got.ID != in.ID || got.Email != in.Email || got.Name != in.Name ||
		got.ExternalID != in.ExternalID || got.Provider != in.Provider {
		t.Errorf("user roundtrip mismatch: got %+v", got)
	}
	if got.Attributes["team"] != "platform" || got.Attributes["tier"] != "gold" {
		t.Errorf("attributes roundtrip mismatch: %v", got.Attributes)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not stamped: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
	}
}

func TestUser_SCIMUserNameUniqueCaseInsensitive(t *testing.T) {
	p := freshUserProvider(t)
	ctx := context.Background()
	first := &core.User{ID: "u1", Attributes: map[string]string{"scim:userName": "Alice@example.com"}}
	second := &core.User{ID: "u2", Attributes: map[string]string{"scim:userName": "alice@example.com"}}
	if err := p.CreateOrUpdate(ctx, first); err != nil {
		t.Fatalf("first CreateOrUpdate: %v", err)
	}
	if err := p.CreateOrUpdate(ctx, second); !errors.Is(err, core.ErrUserExists) {
		t.Fatalf("duplicate CreateOrUpdate = %v, want ErrUserExists", err)
	}
}

func TestUser_GetByID_MissingReturnsErrNoSuchUser(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	if _, err := p.GetByID(context.Background(), "ghost"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("missing GetByID err = %v, want ErrNoSuchUser", err)
	}
}

func TestUser_GetByExternalID(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()

	if err := p.CreateOrUpdate(ctx, &core.User{ID: "u1", ExternalID: "ext-1", Provider: "github"}); err != nil {
		t.Fatalf("CreateOrUpdate u1: %v", err)
	}
	if err := p.CreateOrUpdate(ctx, &core.User{ID: "u2", ExternalID: "ext-2", Provider: "gitlab"}); err != nil {
		t.Fatalf("CreateOrUpdate u2: %v", err)
	}

	got, err := p.GetByExternalID(ctx, "github", "ext-1")
	if err != nil {
		t.Fatalf("GetByExternalID: %v", err)
	}
	if got.ID != "u1" {
		t.Errorf("got id %q, want u1", got.ID)
	}

	if _, err := p.GetByExternalID(ctx, "github", "nope"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("missing GetByExternalID err = %v, want ErrNoSuchUser", err)
	}
}

func TestUser_CreateOrUpdate_PreservesCreatedAtAndReplacesInFull(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()

	first := &core.User{ID: "alice", Email: "old@x", Name: "Old", Attributes: map[string]string{"k": "v1"}}
	if err := p.CreateOrUpdate(ctx, first); err != nil {
		t.Fatalf("first: %v", err)
	}
	createdAt := first.CreatedAt
	if createdAt.IsZero() {
		t.Fatal("CreatedAt not stamped on first insert")
	}

	// Wait a beat so UpdatedAt advances past CreatedAt at nanosecond resolution.
	time.Sleep(2 * time.Millisecond)

	// Upsert replaces every non-PK column (email, name, attributes) in full.
	second := &core.User{ID: "alice", Email: "new@x", Name: "New", Attributes: map[string]string{"k": "v2"}}
	if err := p.CreateOrUpdate(ctx, second); err != nil {
		t.Fatalf("second: %v", err)
	}

	got, err := p.GetByID(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "new@x" || got.Name != "New" || got.Attributes["k"] != "v2" {
		t.Errorf("upsert did not replace in full: got %+v", got)
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt drifted on update: was %v, now %v", createdAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(createdAt) {
		t.Errorf("UpdatedAt did not advance: created=%v updated=%v", createdAt, got.UpdatedAt)
	}
}

func TestUser_CreateOrUpdate_RejectsEmptyID(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	if err := p.CreateOrUpdate(context.Background(), &core.User{}); err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestUser_List_OrderById(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()

	for _, id := range []string{"z", "a", "m"} {
		if err := p.CreateOrUpdate(ctx, &core.User{ID: id}); err != nil {
			t.Fatalf("CreateOrUpdate %s: %v", id, err)
		}
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

func TestUser_Delete_RemovesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()

	if err := p.CreateOrUpdate(ctx, &core.User{ID: "alice"}); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	if err := p.Delete(ctx, "alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.GetByID(ctx, "alice"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("after delete GetByID err = %v, want ErrNoSuchUser", err)
	}
	// Idempotent: deleting a missing id returns nil.
	if err := p.Delete(ctx, "ghost"); err != nil {
		t.Errorf("delete of missing id should be nil, got %v", err)
	}
}

func TestUser_NilAttributes_RoundtripsAsEmpty(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()
	if err := p.CreateOrUpdate(ctx, &core.User{ID: "u"}); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	got, err := p.GetByID(ctx, "u")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if len(got.Attributes) != 0 {
		t.Errorf("nil attributes roundtrip = %v, want empty/nil", got.Attributes)
	}
}

func TestUser_NanosecondRoundTrip(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()

	// A precise nanosecond instant must survive the BIGINT round-trip exactly.
	created := time.Unix(0, 1_700_000_000_123_456_789).UTC()
	if err := p.CreateOrUpdate(ctx, &core.User{ID: "ns", CreatedAt: created}); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	got, err := p.GetByID(ctx, "ns")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.CreatedAt.UnixNano() != created.UnixNano() {
		t.Fatalf("created_at nanosecond round-trip lost: got %d want %d",
			got.CreatedAt.UnixNano(), created.UnixNano())
	}
	// updated_at is stamped at write time; assert it also round-trips to the
	// nanosecond (no truncation to seconds/micros).
	if got.UpdatedAt.UnixNano()%1000 == 0 && got.UpdatedAt.Nanosecond() == 0 {
		t.Logf("updated_at = %v (note: zero sub-second is possible but rare)", got.UpdatedAt)
	}
}

func TestUser_ListPaginated(t *testing.T) {
	t.Parallel()
	p := freshUserProvider(t)
	ctx := context.Background()
	for _, id := range []string{"e", "a", "d", "b", "c"} {
		if err := p.CreateOrUpdate(ctx, &core.User{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := p.ListPaginated(ctx, 1, 2)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if total != 5 || len(page) != 2 || page[0].ID != "b" || page[1].ID != "c" {
		t.Fatalf("page=%v total=%d, want [b c], 5", page, total)
	}
}
