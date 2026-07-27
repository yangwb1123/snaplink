package redis

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestRedisConsentStore_RecordGetRoundTrip(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)
	ctx := context.Background()

	now := time.Now().UTC()
	grant := sso.ConsentGrant{
		UserID:    "u1",
		ClientID:  "c1",
		Scopes:    []string{"profile", "openid", "email"},
		GrantedAt: now,
	}
	if err := cs.RecordConsent(ctx, grant); err != nil {
		t.Fatalf("RecordConsent: %v", err)
	}

	got, err := cs.GetConsent(ctx, "u1", "c1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if got.UserID != "u1" || got.ClientID != "c1" {
		t.Errorf("round-trip identity mismatch: %+v", got)
	}
	// Scopes are normalized (sorted + deduplicated) on record, matching peers.
	want := []string{"email", "openid", "profile"}
	if !reflect.DeepEqual(got.Scopes, want) {
		t.Errorf("scopes = %v, want %v", got.Scopes, want)
	}
	if !got.GrantedAt.Equal(now) {
		t.Errorf("GrantedAt = %v, want %v", got.GrantedAt, now)
	}
}

func TestRedisConsentStore_GetAbsent(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)
	if _, err := cs.GetConsent(context.Background(), "nope", "nope"); !errors.Is(err, sso.ErrNoConsentGrant) {
		t.Errorf("GetConsent absent = %v, want ErrNoConsentGrant", err)
	}
}

func TestRedisConsentStore_RevokeIdempotent(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}, GrantedAt: time.Now()})

	if err := cs.RevokeConsent(ctx, "u1", "c1"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}
	if _, err := cs.GetConsent(ctx, "u1", "c1"); !errors.Is(err, sso.ErrNoConsentGrant) {
		t.Errorf("GetConsent after revoke = %v, want ErrNoConsentGrant", err)
	}
	// Revoking a non-existent grant is a no-op (idempotent).
	if err := cs.RevokeConsent(ctx, "u1", "c1"); err != nil {
		t.Errorf("RevokeConsent (second) = %v, want nil", err)
	}
	if err := cs.RevokeConsent(ctx, "ghost", "ghost"); err != nil {
		t.Errorf("RevokeConsent (unknown) = %v, want nil", err)
	}
}

func TestRedisConsentStore_RevokeDropsFromListByUser(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "c1", GrantedAt: time.Now()})
	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "c2", GrantedAt: time.Now()})
	if err := cs.RevokeConsent(ctx, "u1", "c1"); err != nil {
		t.Fatalf("RevokeConsent: %v", err)
	}

	got, err := cs.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	// Revoked client id must be SREM'd from the index so it doesn't surface as
	// a nil-MGet orphan or leak the revoked grant.
	if len(got) != 1 || got[0].ClientID != "c2" {
		t.Errorf("ListByUser after revoke = %+v, want only c2", got)
	}
}

func TestRedisConsentStore_ListByUserOrdering(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)
	ctx := context.Background()

	base := time.Now().UTC()
	// Insert out of chronological order; ListByUser must return descending
	// GrantedAt (most recent first).
	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "old", GrantedAt: base.Add(-2 * time.Hour)})
	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "new", GrantedAt: base})
	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "mid", GrantedAt: base.Add(-1 * time.Hour)})
	// A grant for a different user must not bleed in.
	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u2", ClientID: "other", GrantedAt: base})

	got, err := cs.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	wantOrder := []string{"new", "mid", "old"}
	if len(got) != len(wantOrder) {
		t.Fatalf("ListByUser len = %d, want %d (%+v)", len(got), len(wantOrder), got)
	}
	for i, cid := range wantOrder {
		if got[i].ClientID != cid {
			t.Errorf("ListByUser[%d].ClientID = %q, want %q", i, got[i].ClientID, cid)
		}
	}
}

func TestRedisConsentStore_ListByUserEmpty(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)

	got, err := cs.ListByUser(context.Background(), "nobody")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	// Empty slice, never nil, never an error.
	if got == nil {
		t.Errorf("ListByUser empty = nil slice, want non-nil empty")
	}
	if len(got) != 0 {
		t.Errorf("ListByUser empty = %+v, want len 0", got)
	}
}

func TestRedisConsentStore_OverwriteReplaces(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewConsentStore(rdb)
	ctx := context.Background()

	first := time.Now().UTC().Add(-time.Hour)
	second := time.Now().UTC()
	_ = cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}, GrantedAt: first})
	// Re-record the same pair: the prior grant is replaced in full (scopes +
	// GrantedAt), not merged.
	if err := cs.RecordConsent(ctx, sso.ConsentGrant{UserID: "u1", ClientID: "c1", Scopes: []string{"email", "profile"}, GrantedAt: second}); err != nil {
		t.Fatalf("RecordConsent (overwrite): %v", err)
	}

	got, err := cs.GetConsent(ctx, "u1", "c1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	wantScopes := []string{"email", "profile"}
	if !reflect.DeepEqual(got.Scopes, wantScopes) {
		t.Errorf("scopes after overwrite = %v, want %v", got.Scopes, wantScopes)
	}
	if !got.GrantedAt.Equal(second) {
		t.Errorf("GrantedAt after overwrite = %v, want %v", got.GrantedAt, second)
	}

	// Overwrite must not duplicate the index entry → ListByUser has exactly one.
	list, err := cs.ListByUser(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("ListByUser after overwrite len = %d, want 1 (%+v)", len(list), list)
	}
}
