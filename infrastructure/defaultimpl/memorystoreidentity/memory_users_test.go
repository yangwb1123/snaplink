package memorystoreidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryUserProvider_CreateThenGet(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	u := &core.User{ID: "u-alice", Email: "alice@example.com", Provider: "password", ExternalID: "alice"}
	if err := p.CreateOrUpdate(context.Background(), u); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	got, err := p.GetByID(context.Background(), "u-alice")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "alice@example.com" {
		t.Errorf("Email = %q", got.Email)
	}
}

func TestMemoryUserProvider_ClonesCreateAttributes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	attrs := map[string]string{core.UserAttrActive: core.UserAttrInactive}
	p := NewMemoryUserProvider()
	user := &core.User{
		ID: "u-copy", Provider: "password", ExternalID: "ext-copy",
		Username: "alice", Email: "alice@example.com", Attributes: attrs,
	}
	if err := p.CreateOrUpdate(ctx, user); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}

	attrs[core.UserAttrActive] = "true"
	attrs["tampered"] = "true"
	assertUserInactive(t, p, ctx)
}

func TestMemoryUserProvider_ClonesLookupAttributes(t *testing.T) {
	t.Parallel()
	p, ctx := newInactiveUserProvider(t)
	lookups := []func() (*core.User, error){
		func() (*core.User, error) { return p.GetByID(ctx, "u-copy") },
		func() (*core.User, error) { return p.GetByExternalID(ctx, "password", "ext-copy") },
		func() (*core.User, error) { return p.GetByUsername(ctx, "alice") },
		func() (*core.User, error) { return p.GetByEmail(ctx, "alice@example.com") },
	}
	for _, lookup := range lookups {
		got, err := lookup()
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		mutateUserAttributes(got)
		assertUserInactive(t, p, ctx)
	}
}

func TestMemoryUserProvider_ClonesListAttributes(t *testing.T) {
	t.Parallel()
	p, ctx := newInactiveUserProvider(t)
	list, err := p.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %v, %v; want one user", list, err)
	}
	mutateUserAttributes(list[0])
	assertUserInactive(t, p, ctx)

	page, _, err := p.ListPaginated(ctx, 0, 10)
	if err != nil || len(page) != 1 {
		t.Fatalf("ListPaginated = %v, %v; want one user", page, err)
	}
	mutateUserAttributes(page[0])
	assertUserInactive(t, p, ctx)

	filtered, _, _, err := p.ListPage(ctx, core.PageQuery{Limit: 10})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("ListPage = %v, %v; want one user", filtered, err)
	}
	mutateUserAttributes(filtered[0])
	assertUserInactive(t, p, ctx)
}

func newInactiveUserProvider(t *testing.T) (*MemoryUserProvider, context.Context) {
	t.Helper()
	ctx := context.Background()
	p := NewMemoryUserProvider()
	user := &core.User{
		ID: "u-copy", Provider: "password", ExternalID: "ext-copy",
		Username: "alice", Email: "alice@example.com",
		Attributes: map[string]string{core.UserAttrActive: core.UserAttrInactive},
	}
	if err := p.CreateOrUpdate(ctx, user); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	return p, ctx
}

func mutateUserAttributes(user *core.User) {
	user.Attributes[core.UserAttrActive] = "true"
	user.Attributes["tampered"] = "true"
}

func assertUserInactive(t *testing.T, p *MemoryUserProvider, ctx context.Context) {
	t.Helper()
	got, err := p.GetByID(ctx, "u-copy")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Attributes[core.UserAttrActive] != core.UserAttrInactive || got.IsActive() {
		t.Fatalf("stored deprovisioning state changed: %+v", got.Attributes)
	}
}

func TestMemoryUserProvider_GetByIDMissing(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	if _, err := p.GetByID(context.Background(), "?"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser", err)
	}
}

func TestMemoryUserProvider_GetByExternalID(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	u := &core.User{ID: "u1", Provider: "ldap", ExternalID: "cn=alice"}
	_ = p.CreateOrUpdate(context.Background(), u)

	got, err := p.GetByExternalID(context.Background(), "ldap", "cn=alice")
	if err != nil {
		t.Fatalf("GetByExternalID: %v", err)
	}
	if got.ID != "u1" {
		t.Errorf("got %+v", got)
	}

	// Wrong provider — must miss even with matching ExternalID.
	if _, err := p.GetByExternalID(context.Background(), "saml", "cn=alice"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("provider mismatch err = %v, want ErrNoSuchUser", err)
	}
	// Wrong external id.
	if _, err := p.GetByExternalID(context.Background(), "ldap", "cn=missing"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("external id mismatch err = %v", err)
	}
}

func TestMemoryUserProvider_RejectsNilOrEmptyID(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	if err := p.CreateOrUpdate(context.Background(), nil); err == nil {
		t.Error("expected error on nil user")
	}
	if err := p.CreateOrUpdate(context.Background(), &core.User{}); err == nil {
		t.Error("expected error on empty ID")
	}
}

func TestMemoryUserProvider_UpdateReplaces(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u", Email: "old@x.com"})
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u", Email: "new@x.com"})
	got, _ := p.GetByID(context.Background(), "u")
	if got.Email != "new@x.com" {
		t.Errorf("Email = %q, want new@x.com (update should replace)", got.Email)
	}
}

func TestMemoryUserProvider_List(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "a"})
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "b"})
	users, _ := p.List(context.Background())
	if len(users) != 2 {
		t.Errorf("List len = %d, want 2", len(users))
	}
}

func TestMemoryUserProvider_Delete(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u"})
	_ = p.Delete(context.Background(), "u")
	if _, err := p.GetByID(context.Background(), "u"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("err = %v", err)
	}
	// Idempotent.
	if err := p.Delete(context.Background(), "u"); err != nil {
		t.Errorf("Delete on already-gone: %v", err)
	}
}

func TestMemoryUserProvider_Delete_ClearsIndices(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u", Username: "Alice", Email: "Alice@example.com"})
	_ = p.Delete(context.Background(), "u")

	if _, err := p.GetByUsername(context.Background(), "alice"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("GetByUsername after delete: err = %v, want ErrNoSuchUser", err)
	}
	if _, err := p.GetByEmail(context.Background(), "alice@example.com"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("GetByEmail after delete: err = %v, want ErrNoSuchUser", err)
	}

	// The username/email must be free for a different user to claim.
	if err := p.CreateOrUpdate(context.Background(), &core.User{ID: "v", Username: "alice", Email: "alice@example.com"}); err != nil {
		t.Errorf("re-registering freed username/email: %v", err)
	}
}

func TestMemoryUserProvider_GetByUsername(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u-bob", Username: "Bob"})

	// Case-insensitive match.
	got, err := p.GetByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != "u-bob" {
		t.Errorf("got %+v", got)
	}

	if _, err := p.GetByUsername(context.Background(), "nobody"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser", err)
	}
}

func TestMemoryUserProvider_GetByEmail(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u-carol", Email: "Carol@Example.com"})

	got, err := p.GetByEmail(context.Background(), "carol@example.com")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if got.ID != "u-carol" {
		t.Errorf("got %+v", got)
	}

	if _, err := p.GetByEmail(context.Background(), "missing@example.com"); !errors.Is(err, core.ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser", err)
	}
}

func TestMemoryUserProvider_UsernameExists(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u", Username: "dave"})

	if ok, err := p.UsernameExists(context.Background(), "DAVE"); err != nil || !ok {
		t.Errorf("UsernameExists(DAVE) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := p.UsernameExists(context.Background(), "erin"); err != nil || ok {
		t.Errorf("UsernameExists(erin) = %v, %v; want false, nil", ok, err)
	}
}

func TestMemoryUserProvider_EmailExists(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u", Email: "frank@example.com"})

	if ok, err := p.EmailExists(context.Background(), "FRANK@example.com"); err != nil || !ok {
		t.Errorf("EmailExists(FRANK@example.com) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := p.EmailExists(context.Background(), "grace@example.com"); err != nil || ok {
		t.Errorf("EmailExists(grace@example.com) = %v, %v; want false, nil", ok, err)
	}
}

func TestMemoryUserProvider_ListPaginated(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	ids := []string{"c", "a", "e", "b", "d"}
	for _, id := range ids {
		_ = p.CreateOrUpdate(context.Background(), &core.User{ID: id})
	}

	page, total, err := p.ListPaginated(context.Background(), 1, 2)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(page) != 2 || page[0].ID != "b" || page[1].ID != "c" {
		t.Errorf("page = %+v, want [b c] (sorted by ID)", page)
	}

	// offset past the end returns an empty page, not an error.
	page, total, err = p.ListPaginated(context.Background(), 100, 10)
	if err != nil {
		t.Fatalf("ListPaginated offset past end: %v", err)
	}
	if total != 5 || len(page) != 0 {
		t.Errorf("page = %+v, total = %d; want empty page, total 5", page, total)
	}

	// limit <= 0 defaults to 10; limit > 100 clamps to 100. Verify the
	// default by requesting 0 and confirming it returns more than a literal
	// zero-length page (all 5 available users, since 5 < default of 10).
	page, _, err = p.ListPaginated(context.Background(), 0, 0)
	if err != nil {
		t.Fatalf("ListPaginated limit=0: %v", err)
	}
	if len(page) != 5 {
		t.Errorf("limit=0 (default) page len = %d, want 5", len(page))
	}
}

// TestMemoryUserProvider_CreateOrUpdate_RejectedUpdatePreservesOldIndex is a
// regression test: CreateOrUpdate must validate username/email uniqueness
// BEFORE mutating either index. An earlier version deleted the existing
// user's old index entries first and only then checked uniqueness, so a
// rejected update left that user unfindable by GetByUsername/GetByEmail even
// though the update never actually applied.
func TestMemoryUserProvider_CreateOrUpdate_RejectedUpdatePreservesOldIndex(t *testing.T) {
	t.Parallel()
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u-holder", Username: "taken", Email: "taken@example.com"})
	_ = p.CreateOrUpdate(context.Background(), &core.User{ID: "u-victim", Username: "victim", Email: "victim@example.com"})

	// Attempt to steal "taken"/"taken@example.com" for u-victim — must be rejected.
	err := p.CreateOrUpdate(context.Background(), &core.User{ID: "u-victim", Username: "taken", Email: "taken@example.com"})
	if !errors.Is(err, core.ErrUserExists) {
		t.Fatalf("err = %v, want ErrUserExists", err)
	}

	// u-victim's OWN username/email must still resolve — the rejected update
	// must not have stranded the old index entries.
	got, err := p.GetByUsername(context.Background(), "victim")
	if err != nil {
		t.Fatalf("GetByUsername(victim) after rejected update: %v", err)
	}
	if got.ID != "u-victim" {
		t.Errorf("got %+v", got)
	}
	got, err = p.GetByEmail(context.Background(), "victim@example.com")
	if err != nil {
		t.Fatalf("GetByEmail(victim@example.com) after rejected update: %v", err)
	}
	if got.ID != "u-victim" {
		t.Errorf("got %+v", got)
	}

	// u-holder must still own "taken"/"taken@example.com" untouched.
	got, err = p.GetByUsername(context.Background(), "taken")
	if err != nil || got.ID != "u-holder" {
		t.Errorf("GetByUsername(taken) = %+v, %v; want u-holder, nil", got, err)
	}
}
