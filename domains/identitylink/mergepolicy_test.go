package identitylink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/domains/identitylink/memory"
)

func TestRejectPolicy_AlwaysRefuses(t *testing.T) {
	p := identitylink.RejectPolicy{}
	decision, err := p.Resolve(context.Background(), identitylink.Conflict{
		Provider: "google", Subject: "sub-1", ExistingUserID: "u1", IncomingUserID: "u2",
	})
	if decision.Allow {
		t.Fatalf("RejectPolicy.Resolve: Allow = true, want false")
	}
	if !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Errorf("RejectPolicy.Resolve error = %v, want ErrAccountConflict", err)
	}
}

func TestResolve_NoStore_ReturnsIncomingUnchanged(t *testing.T) {
	got, err := identitylink.Resolve(context.Background(), nil, nil, "google", "sub-1", "incoming-user")
	if err != nil {
		t.Fatalf("Resolve with nil store: err = %v, want nil", err)
	}
	if got != "incoming-user" {
		t.Errorf("Resolve with nil store = %q, want %q", got, "incoming-user")
	}
}

func TestResolve_NoConflict_ReturnsIncomingUnchanged(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	// incoming-user already owns this exact (provider, subject) pair - no conflict.
	if _, err := store.Link(ctx, "incoming-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	got, err := identitylink.Resolve(ctx, store, identitylink.RejectPolicy{}, "google", "sub-1", "incoming-user")
	if err != nil {
		t.Fatalf("Resolve same-owner: err = %v, want nil", err)
	}
	if got != "incoming-user" {
		t.Errorf("Resolve same-owner = %q, want %q", got, "incoming-user")
	}
}

func TestResolve_Conflict_NilPolicyRejectsByDefault(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	if _, err := store.Link(ctx, "existing-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	// A DIFFERENT incoming user authenticates with the same (provider, subject).
	_, err := identitylink.Resolve(ctx, store, nil, "google", "sub-1", "incoming-user")
	if !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Errorf("Resolve conflict with nil policy: err = %v, want ErrAccountConflict (safe default)", err)
	}
}

func TestResolve_Conflict_ExplicitRejectPolicy(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	if _, err := store.Link(ctx, "existing-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed link: %v", err)
	}
	_, err := identitylink.Resolve(ctx, store, identitylink.RejectPolicy{}, "google", "sub-1", "incoming-user")
	if !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Errorf("Resolve conflict with RejectPolicy: err = %v, want ErrAccountConflict", err)
	}
}

func TestResolve_Conflict_LinkOnlyMergePolicy(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	if _, err := store.Link(ctx, "existing-user", "google", "sub-1"); err != nil {
		t.Fatalf("seed existing link: %v", err)
	}
	// The incoming (losing) account has an UNRELATED extra link that should
	// travel with the merge.
	if _, err := store.Link(ctx, "incoming-user", "github", "gh-42"); err != nil {
		t.Fatalf("seed incoming link: %v", err)
	}

	policy := identitylink.NewLinkOnlyMergePolicy(store)
	final, err := identitylink.Resolve(ctx, store, policy, "google", "sub-1", "incoming-user")
	if err != nil {
		t.Fatalf("Resolve with LinkOnlyMergePolicy: err = %v, want nil", err)
	}
	if final != "existing-user" {
		t.Errorf("Resolve with LinkOnlyMergePolicy = %q, want %q (existing account wins)", final, "existing-user")
	}

	// The github link must have moved onto the winning account...
	winnerLinks, err := store.ListByUser(ctx, "existing-user")
	if err != nil {
		t.Fatalf("ListByUser(existing-user): %v", err)
	}
	if !hasProviderSubject(winnerLinks, "github", "gh-42") {
		t.Errorf("winning account missing merged github link: %+v", winnerLinks)
	}
	if !hasProviderSubject(winnerLinks, "google", "sub-1") {
		t.Errorf("winning account missing its own google link: %+v", winnerLinks)
	}

	// ...and the losing account must have NO active links left.
	loserLinks, err := store.ListByUser(ctx, "incoming-user")
	if err != nil {
		t.Fatalf("ListByUser(incoming-user): %v", err)
	}
	if len(loserLinks) != 0 {
		t.Errorf("losing account still has active links: %+v", loserLinks)
	}
}

func TestLinkOnlyMergePolicy_NoStore(t *testing.T) {
	p := &identitylink.LinkOnlyMergePolicy{}
	_, err := p.Resolve(context.Background(), identitylink.Conflict{ExistingUserID: "a", IncomingUserID: "b"})
	if !errors.Is(err, identitylink.ErrAccountConflict) {
		t.Errorf("LinkOnlyMergePolicy with no store: err = %v, want ErrAccountConflict", err)
	}
}

func hasProviderSubject(links []identitylink.Identity, provider, subject string) bool {
	for _, l := range links {
		if l.Provider == provider && l.Subject == subject {
			return true
		}
	}
	return false
}
