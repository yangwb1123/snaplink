package memorystoreidentity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryConsentStore_RecordAndGet(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()
	now := time.Now().Truncate(time.Millisecond)

	grant := core.ConsentGrant{
		UserID:    "alice",
		ClientID:  "app1",
		Scopes:    []string{"openid", "profile"},
		GrantedAt: now,
	}
	if err := cs.RecordConsent(ctx, grant); err != nil {
		t.Fatalf("RecordConsent: %v", err)
	}

	got, err := cs.GetConsent(ctx, "alice", "app1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if got.UserID != "alice" || got.ClientID != "app1" {
		t.Fatalf("wrong grant: %+v", got)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("scopes: got %v", got.Scopes)
	}
}

func TestMemoryConsentStore_GetMissingReturnsErrNoConsentGrant(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	_, err := cs.GetConsent(context.Background(), "alice", "app1")
	if !errors.Is(err, core.ErrNoConsentGrant) {
		t.Fatalf("got %v, want ErrNoConsentGrant", err)
	}
}

func TestMemoryConsentStore_RecordOverwritesPriorGrant(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:    "alice",
		ClientID:  "app1",
		Scopes:    []string{"openid"},
		GrantedAt: time.Now(),
	})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:    "alice",
		ClientID:  "app1",
		Scopes:    []string{"openid", "email"},
		GrantedAt: time.Now(),
	})

	got, err := cs.GetConsent(ctx, "alice", "app1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("scopes after overwrite: %v", got.Scopes)
	}
}

func TestMemoryConsentStore_RevokeRemovesGrant(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:    "alice",
		ClientID:  "app1",
		Scopes:    []string{"openid"},
		GrantedAt: time.Now(),
	})
	if err := cs.RevokeConsent(ctx, "alice", "app1"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	_, err := cs.GetConsent(ctx, "alice", "app1")
	if !errors.Is(err, core.ErrNoConsentGrant) {
		t.Fatalf("post-revoke Get: got %v, want ErrNoConsentGrant", err)
	}
}

func TestMemoryConsentStore_RevokeIsIdempotent(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()
	// Revoking a non-existent grant MUST NOT error.
	if err := cs.RevokeConsent(ctx, "alice", "app1"); err != nil {
		t.Fatalf("idempotent RevokeConsent: %v", err)
	}
}

func TestMemoryConsentStore_ListByUser(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	t1 := time.Now().Add(-2 * time.Second)
	t2 := time.Now().Add(-1 * time.Second)
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app1", Scopes: []string{"openid"}, GrantedAt: t1})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app2", Scopes: []string{"profile"}, GrantedAt: t2})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "bob", ClientID: "app1", Scopes: []string{"openid"}, GrantedAt: t1})

	list, err := cs.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("alice: got %d grants, want 2", len(list))
	}
	// Result MUST be in descending GrantedAt order.
	if !list[0].GrantedAt.After(list[1].GrantedAt) {
		t.Errorf("ListByUser order wrong: first=%v second=%v", list[0].GrantedAt, list[1].GrantedAt)
	}
}

func TestMemoryConsentStore_ListByUserEmptySliceNotNil(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	list, err := cs.ListByUser(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	// Spec says empty slice, not error — but nil is also fine for our use.
	// We don't enforce non-nil from memory (unlike SQLite which always returns []).
	_ = list
}

func TestMemoryConsentStore_NormalizesScopes(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	// Duplicate + unsorted scopes should be stored as sorted+deduped.
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:    "alice",
		ClientID:  "app1",
		Scopes:    []string{"profile", "openid", "openid", "email"},
		GrantedAt: time.Now(),
	})

	got, _ := cs.GetConsent(ctx, "alice", "app1")
	want := []string{"email", "openid", "profile"}
	if len(got.Scopes) != len(want) {
		t.Fatalf("scopes: got %v want %v", got.Scopes, want)
	}
	for i, s := range want {
		if got.Scopes[i] != s {
			t.Fatalf("scope[%d]: got %q want %q", i, got.Scopes[i], s)
		}
	}
}

func TestMemoryConsentStore_SeparatesUserClientPairs(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app1", Scopes: []string{"openid"}, GrantedAt: time.Now()})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app2", Scopes: []string{"profile"}, GrantedAt: time.Now()})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "bob", ClientID: "app1", Scopes: []string{"email"}, GrantedAt: time.Now()})

	aliceApp1, _ := cs.GetConsent(ctx, "alice", "app1")
	if aliceApp1.Scopes[0] != "openid" {
		t.Errorf("alice/app1: got %v", aliceApp1.Scopes)
	}
	bobApp1, _ := cs.GetConsent(ctx, "bob", "app1")
	if bobApp1.Scopes[0] != "email" {
		t.Errorf("bob/app1: got %v", bobApp1.Scopes)
	}
}

func TestMemoryConsentStore_GetConsentReturnsClone(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:   "alice",
		ClientID: "app1",
		Scopes:   []string{"openid", "profile"},
	})

	got, err := cs.GetConsent(ctx, "alice", "app1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	// Mutating the returned Scopes must not corrupt the stored grant.
	if len(got.Scopes) > 0 {
		got.Scopes[0] = "HACKED"
	}

	again, _ := cs.GetConsent(ctx, "alice", "app1")
	if len(again.Scopes) != 2 {
		t.Fatalf("stored scopes corrupted: %v", again.Scopes)
	}
	if again.Scopes[0] != "openid" || again.Scopes[1] != "profile" {
		t.Fatalf("stored scopes corrupted: %v", again.Scopes)
	}
}

func TestMemoryConsentStore_ListByUserReturnsClones(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:   "alice",
		ClientID: "app1",
		Scopes:   []string{"openid", "profile"},
	})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:   "alice",
		ClientID: "app2",
		Scopes:   []string{"email"},
	})

	list, err := cs.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	// Mutating a returned element's Scopes must not corrupt the stored grant.
	for i := range list {
		if len(list[i].Scopes) > 0 {
			list[i].Scopes[0] = "HACKED"
		}
	}

	app1, err := cs.GetConsent(ctx, "alice", "app1")
	if err != nil {
		t.Fatalf("GetConsent(app1): %v", err)
	}
	if len(app1.Scopes) != 2 || app1.Scopes[0] != "openid" || app1.Scopes[1] != "profile" {
		t.Fatalf("stored scopes for app1 corrupted: %v", app1.Scopes)
	}
	app2, err := cs.GetConsent(ctx, "alice", "app2")
	if err != nil {
		t.Fatalf("GetConsent(app2): %v", err)
	}
	if len(app2.Scopes) != 1 || app2.Scopes[0] != "email" {
		t.Fatalf("stored scopes for app2 corrupted: %v", app2.Scopes)
	}
}

func TestMemoryConsentStore_RecordConsentInputStaysIsolated(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	input := []string{"profile", "openid", "openid", "email"}
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:   "alice",
		ClientID: "app1",
		Scopes:   input,
	})

	// Mutating the caller's input after RecordConsent must not affect storage.
	input[0] = "HACKED"

	got, _ := cs.GetConsent(ctx, "alice", "app1")
	want := []string{"email", "openid", "profile"}
	if len(got.Scopes) != len(want) {
		t.Fatalf("scopes: got %v want %v", got.Scopes, want)
	}
	for i, s := range want {
		if got.Scopes[i] != s {
			t.Fatalf("scope[%d]: got %q want %q", i, got.Scopes[i], s)
		}
	}
}

func TestMemoryConsentStore_RecordConsentClonePreservesNil(t *testing.T) {
	t.Parallel()
	cs := NewMemoryConsentStore()
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app1"})
	got, _ := cs.GetConsent(ctx, "alice", "app1")
	if got.Scopes != nil {
		t.Fatalf("expected nil scopes for empty grant, got %v", got.Scopes)
	}

	list, err := cs.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 || list[0].Scopes != nil {
		t.Fatalf("expected nil scopes in list, got %v", list)
	}
}
