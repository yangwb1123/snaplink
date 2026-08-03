package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestRedisUserProvider_CreateGetRoundTrip(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()

	u := &sso.User{ID: "u1", Email: "a@x.test", Name: "Alice", Provider: "oidc", ExternalID: "ext-1"}
	if err := up.CreateOrUpdate(ctx, u); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	got, err := up.GetByID(ctx, "u1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "a@x.test" || got.Name != "Alice" || got.ExternalID != "ext-1" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestRedisUserProvider_UserNameClaimLifecycle(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()
	if err := up.CreateOrUpdate(ctx, &sso.User{ID: "u1", Username: "Alice"}); err != nil {
		t.Fatal(err)
	}
	if err := up.CreateOrUpdate(ctx, &sso.User{ID: "u2", Username: "alice"}); !errors.Is(err, sso.ErrUserExists) {
		t.Fatalf("duplicate username = %v, want ErrUserExists", err)
	}
	if err := up.CreateOrUpdate(ctx, &sso.User{ID: "u1", Username: "Bob"}); err != nil {
		t.Fatal(err)
	}
	if err := up.CreateOrUpdate(ctx, &sso.User{ID: "u2", Username: "Alice"}); err != nil {
		t.Fatalf("released username could not be reclaimed: %v", err)
	}
	got, err := up.GetByUsername(ctx, "ALICE")
	if err != nil || got.ID != "u2" {
		t.Fatalf("GetByUsername = %+v, %v; want u2", got, err)
	}
	if err := up.Delete(ctx, "u2"); err != nil {
		t.Fatal(err)
	}
	if exists, err := up.UsernameExists(ctx, "alice"); err != nil || exists {
		t.Fatalf("UsernameExists after delete = %v, %v; want false, nil", exists, err)
	}
}

func TestRedisUserProvider_GetByIDUnknown(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	if _, err := up.GetByID(context.Background(), "nope"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("GetByID unknown = %v, want ErrNoSuchUser", err)
	}
}

func TestRedisUserProvider_GetByExternalID(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()
	_ = up.CreateOrUpdate(ctx, &sso.User{ID: "u2", Provider: "saml", ExternalID: "saml-99"})

	got, err := up.GetByExternalID(ctx, "saml", "saml-99")
	if err != nil {
		t.Fatalf("GetByExternalID: %v", err)
	}
	if got.ID != "u2" {
		t.Errorf("GetByExternalID id = %q, want u2", got.ID)
	}
	// Unknown external id and empty inputs all map to ErrNoSuchUser.
	if _, err := up.GetByExternalID(ctx, "saml", "missing"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("unknown ext id = %v, want ErrNoSuchUser", err)
	}
	if _, err := up.GetByExternalID(ctx, "saml", ""); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("empty ext id = %v, want ErrNoSuchUser", err)
	}
}

// TestRedisUserProvider_ExternalIDReindexedOnChange verifies the stale pointer
// key is dropped when a user's external identity changes.
func TestRedisUserProvider_ExternalIDReindexedOnChange(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()
	_ = up.CreateOrUpdate(ctx, &sso.User{ID: "u3", Provider: "oidc", ExternalID: "old"})
	// Change the external id.
	_ = up.CreateOrUpdate(ctx, &sso.User{ID: "u3", Provider: "oidc", ExternalID: "new"})

	if _, err := up.GetByExternalID(ctx, "oidc", "old"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("old external id still resolves after re-index: %v", err)
	}
	got, err := up.GetByExternalID(ctx, "oidc", "new")
	if err != nil || got.ID != "u3" {
		t.Errorf("new external id = (%v, %v), want u3", got, err)
	}
}

func TestRedisUserProvider_ListAndDelete(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		_ = up.CreateOrUpdate(ctx, &sso.User{ID: id, Provider: "oidc", ExternalID: "ext-" + id})
	}
	users, err := up.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 3 {
		t.Errorf("List len = %d, want 3", len(users))
	}

	if err := up.Delete(ctx, "b"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := up.GetByID(ctx, "b"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("user present after delete")
	}
	// The deleted user's external-id pointer is gone too.
	if _, err := up.GetByExternalID(ctx, "oidc", "ext-b"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("external-id pointer survived delete")
	}
	users, _ = up.List(ctx)
	if len(users) != 2 {
		t.Errorf("List after delete = %d, want 2", len(users))
	}
	// Second delete is a no-op (idempotent).
	if err := up.Delete(ctx, "b"); err != nil {
		t.Errorf("idempotent Delete = %v, want nil", err)
	}
}

func TestRedisUserProvider_ListPaginated(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()
	for _, id := range []string{"e", "a", "d", "b", "c"} {
		if err := up.CreateOrUpdate(ctx, &sso.User{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	page, total, err := up.ListPaginated(ctx, 1, 2)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if total != 5 || len(page) != 2 || page[0].ID != "b" || page[1].ID != "c" {
		t.Fatalf("page=%v total=%d, want [b c], 5", page, total)
	}
	empty, total, err := up.ListPaginated(ctx, 99, 10)
	if err != nil || total != 5 || len(empty) != 0 {
		t.Fatalf("past-end page=%v total=%d err=%v", empty, total, err)
	}
}

func TestRedisUserProvider_ListPaginatedMigratesLegacyIndex(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	up := NewUserProvider(rdb)
	ctx := context.Background()
	for _, id := range []string{"c", "a", "b"} {
		if err := up.CreateOrUpdate(ctx, &sso.User{ID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if err := rdb.Del(ctx, userPageKey, userPageReadyKey).Err(); err != nil {
		t.Fatal(err)
	}
	page, total, err := up.ListPaginated(ctx, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(page) != 2 || page[0].ID != "a" || page[1].ID != "b" {
		t.Fatalf("migrated page=%v total=%d, want [a b], 3", page, total)
	}
}
