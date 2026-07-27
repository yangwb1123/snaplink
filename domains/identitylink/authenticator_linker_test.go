package identitylink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/identitylink"
	"github.com/yangwb1123/snaplink/domains/identitylink/memory"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestAuthenticatorLinker_FirstLoginNoConflict covers the everyday case: a
// (provider, subject) pair nobody has ever linked anything to. ResolveUserID
// must return the subject unchanged — byte-identical to no linker being
// wired at all — and must NOT create a link record itself (linking is a
// separate, deliberate act; see the adapter's doc).
func TestAuthenticatorLinker_FirstLoginNoConflict(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.New()
	linker := identitylink.NewAuthenticatorLinker(store, identitylink.RejectPolicy{}, nil)

	got, err := linker.ResolveUserID(ctx, "google", "sub-new")
	if err != nil {
		t.Fatalf("ResolveUserID first login: err = %v, want nil", err)
	}
	if got != "sub-new" {
		t.Errorf("ResolveUserID first login = %q, want %q (unchanged)", got, "sub-new")
	}

	links, err := store.ListByUser(ctx, "sub-new")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(links) != 0 {
		t.Errorf("ResolveUserID must not auto-Link — got %d links, want 0", len(links))
	}
}

// TestAuthenticatorLinker_ConflictRejectPolicyFailsClosed reproduces a
// genuine conflict — (provider, subject) already linked to a different
// account by some prior self-service action — and confirms the default
// RejectPolicy refuses the login.
func TestAuthenticatorLinker_ConflictRejectPolicyFailsClosed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.New()
	if _, err := store.Link(ctx, "existing-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	linker := identitylink.NewAuthenticatorLinker(store, identitylink.RejectPolicy{}, nil)

	_, err := linker.ResolveUserID(ctx, "google", "sub-1")
	if !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Fatalf("ResolveUserID conflict with RejectPolicy: err = %v, want ErrAccountConflict", err)
	}
}

// TestAuthenticatorLinker_ConflictAudited proves ResolveUserID emits the
// merge-decision audit event via RecordMergeDecision on a genuine conflict —
// the ready-made adapter must not silently skip the "every merge decision is
// audited" invariant a hand-written integration would have to honor itself.
func TestAuthenticatorLinker_ConflictAudited(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.New()
	if _, err := store.Link(ctx, "existing-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	sink := audit.NewMemorySink(10)
	recorder := audit.New(sink)
	linker := identitylink.NewAuthenticatorLinker(store, identitylink.RejectPolicy{}, recorder)

	if _, err := linker.ResolveUserID(ctx, "google", "sub-1"); !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Fatalf("ResolveUserID: err = %v, want ErrAccountConflict", err)
	}

	events, err := sink.Query(ctx, audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	if events[0].Type != audit.EventIdentityMergeRejected {
		t.Errorf("event type = %q, want %q", events[0].Type, audit.EventIdentityMergeRejected)
	}
}

// TestAuthenticatorLinker_ConflictLinkOnlyMergePolicyMerges confirms the
// opt-in LinkOnlyMergePolicy resolves the conflict onto the winning account
// and the login proceeds as that account.
func TestAuthenticatorLinker_ConflictLinkOnlyMergePolicyMerges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.New()
	if _, err := store.Link(ctx, "existing-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	linker := identitylink.NewAuthenticatorLinker(store, identitylink.NewLinkOnlyMergePolicy(store), nil)

	got, err := linker.ResolveUserID(ctx, "google", "sub-1")
	if err != nil {
		t.Fatalf("ResolveUserID conflict with LinkOnlyMergePolicy: err = %v, want nil", err)
	}
	if got != "existing-user" {
		t.Errorf("ResolveUserID conflict with LinkOnlyMergePolicy = %q, want %q", got, "existing-user")
	}
}

// TestAuthenticatorLinker_SatisfiesUserLinkerShape is a compile-time-ish
// smoke test that AuthenticatorLinker's method signature matches the
// authenticators.UserLinker shape (provider, subject string) -> (string,
// error) WITHOUT this package importing domains/authenticators — structural
// typing only. A local shape-alias interface stands in for the real one so
// this test doesn't need the import either.
func TestAuthenticatorLinker_SatisfiesUserLinkerShape(t *testing.T) {
	t.Parallel()
	type userLinkerShape interface {
		ResolveUserID(ctx context.Context, provider, subject string) (string, error)
	}
	var _ userLinkerShape = (*identitylink.AuthenticatorLinker)(nil)
}
