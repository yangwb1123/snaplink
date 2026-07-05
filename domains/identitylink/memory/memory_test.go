package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/identitylink"
)

func TestStore_LinkListUnlink(t *testing.T) {
	ctx := context.Background()
	s := New()

	link, err := s.Link(ctx, "user-1", "google", "sub-1")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if link.Status != identitylink.StatusActive {
		t.Errorf("Link status = %q, want active", link.Status)
	}

	links, err := s.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(links) != 1 || links[0].ID != link.ID {
		t.Fatalf("ListByUser = %+v, want one link with id %q", links, link.ID)
	}

	if err := s.Unlink(ctx, "user-1", link.ID); err != nil {
		t.Fatalf("Unlink: %v", err)
	}
	links, err = s.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListByUser after unlink: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("ListByUser after unlink = %+v, want empty", links)
	}
}

func TestStore_LinkIdempotent(t *testing.T) {
	ctx := context.Background()
	s := New()
	first, err := s.Link(ctx, "user-1", "google", "sub-1")
	if err != nil {
		t.Fatalf("first Link: %v", err)
	}
	second, err := s.Link(ctx, "user-1", "google", "sub-1")
	if err != nil {
		t.Fatalf("second Link: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("relinking the same (user, provider, subject) minted a new id: %q != %q", first.ID, second.ID)
	}
	links, _ := s.ListByUser(ctx, "user-1")
	if len(links) != 1 {
		t.Errorf("relinking created a duplicate: %+v", links)
	}
}

func TestStore_UnlinkWrongOwner(t *testing.T) {
	ctx := context.Background()
	s := New()
	link, _ := s.Link(ctx, "user-1", "google", "sub-1")

	err := s.Unlink(ctx, "user-2", link.ID)
	if !errors.Is(err, identitylink.ErrNotFound) {
		t.Errorf("Unlink wrong owner = %v, want ErrNotFound", err)
	}
	// The link must still be active for its real owner (oracle-safe: the
	// failed cross-user unlink must not have side effects).
	links, _ := s.ListByUser(ctx, "user-1")
	if len(links) != 1 {
		t.Errorf("cross-user unlink attempt mutated the real owner's links: %+v", links)
	}
}

func TestStore_UnlinkUnknownID(t *testing.T) {
	ctx := context.Background()
	s := New()
	if err := s.Unlink(ctx, "user-1", "does-not-exist"); !errors.Is(err, identitylink.ErrNotFound) {
		t.Errorf("Unlink unknown id = %v, want ErrNotFound", err)
	}
}

func TestStore_UnlinkAlreadyRevoked(t *testing.T) {
	ctx := context.Background()
	s := New()
	link, _ := s.Link(ctx, "user-1", "google", "sub-1")
	if err := s.Unlink(ctx, "user-1", link.ID); err != nil {
		t.Fatalf("first Unlink: %v", err)
	}
	if err := s.Unlink(ctx, "user-1", link.ID); !errors.Is(err, identitylink.ErrNotFound) {
		t.Errorf("double Unlink = %v, want ErrNotFound", err)
	}
}

func TestStore_FindByProviderSubject(t *testing.T) {
	ctx := context.Background()
	s := New()
	link, _ := s.Link(ctx, "user-1", "google", "sub-1")

	found, ok, err := s.FindByProviderSubject(ctx, "google", "sub-1")
	if err != nil {
		t.Fatalf("FindByProviderSubject: %v", err)
	}
	if !ok || found.ID != link.ID {
		t.Fatalf("FindByProviderSubject = %+v, ok=%v, want %+v, true", found, ok, link)
	}

	if _, ok, _ := s.FindByProviderSubject(ctx, "google", "no-such-sub"); ok {
		t.Errorf("FindByProviderSubject unknown subject: ok = true, want false")
	}

	// After unlinking, the pair must no longer resolve (revoked links don't
	// count as an active claim on the provider+subject pair).
	_ = s.Unlink(ctx, "user-1", link.ID)
	if _, ok, _ := s.FindByProviderSubject(ctx, "google", "sub-1"); ok {
		t.Errorf("FindByProviderSubject after unlink: ok = true, want false")
	}
}

func TestStore_MultipleUsersIsolated(t *testing.T) {
	ctx := context.Background()
	s := New()
	_, _ = s.Link(ctx, "user-1", "google", "sub-1")
	_, _ = s.Link(ctx, "user-1", "github", "gh-1")
	_, _ = s.Link(ctx, "user-2", "google", "sub-2")

	links1, _ := s.ListByUser(ctx, "user-1")
	links2, _ := s.ListByUser(ctx, "user-2")
	if len(links1) != 2 {
		t.Errorf("user-1 links = %+v, want 2", links1)
	}
	if len(links2) != 1 {
		t.Errorf("user-2 links = %+v, want 1", links2)
	}
}

var _ identitylink.Store = (*Store)(nil)
