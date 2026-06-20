package defaultimpl

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

func TestMemoryUserProvider_CreateThenGet(t *testing.T) {
	p := NewMemoryUserProvider()
	u := &sso.User{ID: "u-alice", Email: "alice@example.com", Provider: "password", ExternalID: "alice"}
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

func TestMemoryUserProvider_GetByIDMissing(t *testing.T) {
	p := NewMemoryUserProvider()
	if _, err := p.GetByID(context.Background(), "?"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("err = %v, want ErrNoSuchUser", err)
	}
}

func TestMemoryUserProvider_GetByExternalID(t *testing.T) {
	p := NewMemoryUserProvider()
	u := &sso.User{ID: "u1", Provider: "ldap", ExternalID: "cn=alice"}
	_ = p.CreateOrUpdate(context.Background(), u)

	got, err := p.GetByExternalID(context.Background(), "ldap", "cn=alice")
	if err != nil {
		t.Fatalf("GetByExternalID: %v", err)
	}
	if got.ID != "u1" {
		t.Errorf("got %+v", got)
	}

	// Wrong provider — must miss even with matching ExternalID.
	if _, err := p.GetByExternalID(context.Background(), "saml", "cn=alice"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("provider mismatch err = %v, want ErrNoSuchUser", err)
	}
	// Wrong external id.
	if _, err := p.GetByExternalID(context.Background(), "ldap", "cn=missing"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("external id mismatch err = %v", err)
	}
}

func TestMemoryUserProvider_RejectsNilOrEmptyID(t *testing.T) {
	p := NewMemoryUserProvider()
	if err := p.CreateOrUpdate(context.Background(), nil); err == nil {
		t.Error("expected error on nil user")
	}
	if err := p.CreateOrUpdate(context.Background(), &sso.User{}); err == nil {
		t.Error("expected error on empty ID")
	}
}

func TestMemoryUserProvider_UpdateReplaces(t *testing.T) {
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &sso.User{ID: "u", Email: "old@x.com"})
	_ = p.CreateOrUpdate(context.Background(), &sso.User{ID: "u", Email: "new@x.com"})
	got, _ := p.GetByID(context.Background(), "u")
	if got.Email != "new@x.com" {
		t.Errorf("Email = %q, want new@x.com (update should replace)", got.Email)
	}
}

func TestMemoryUserProvider_List(t *testing.T) {
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &sso.User{ID: "a"})
	_ = p.CreateOrUpdate(context.Background(), &sso.User{ID: "b"})
	users, _ := p.List(context.Background())
	if len(users) != 2 {
		t.Errorf("List len = %d, want 2", len(users))
	}
}

func TestMemoryUserProvider_Delete(t *testing.T) {
	p := NewMemoryUserProvider()
	_ = p.CreateOrUpdate(context.Background(), &sso.User{ID: "u"})
	_ = p.Delete(context.Background(), "u")
	if _, err := p.GetByID(context.Background(), "u"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("err = %v", err)
	}
	// Idempotent.
	if err := p.Delete(context.Background(), "u"); err != nil {
		t.Errorf("Delete on already-gone: %v", err)
	}
}
