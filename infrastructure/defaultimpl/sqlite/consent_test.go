package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/shared/core"
)

func newTestConsentStore(t *testing.T) *sqlite.ConsentStore {
	t.Helper()
	cs, err := sqlite.NewConsentStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("NewConsentStore: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestSQLiteConsentStore_RecordAndGet(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
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

func TestSQLiteConsentStore_GetMissingReturnsErrNoConsentGrant(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	_, err := cs.GetConsent(context.Background(), "alice", "app1")
	if !errors.Is(err, core.ErrNoConsentGrant) {
		t.Fatalf("got %v, want ErrNoConsentGrant", err)
	}
}

func TestSQLiteConsentStore_RecordOverwritesPriorGrant(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
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

func TestSQLiteConsentStore_RevokeRemovesGrant(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
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

func TestSQLiteConsentStore_RevokeIsIdempotent(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	// Revoking a non-existent grant MUST NOT error.
	if err := cs.RevokeConsent(context.Background(), "alice", "app1"); err != nil {
		t.Fatalf("idempotent RevokeConsent: %v", err)
	}
}

func TestSQLiteConsentStore_ListByUser(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	ctx := context.Background()

	t1 := time.Now().Add(-2 * time.Second).Truncate(time.Millisecond)
	t2 := time.Now().Add(-1 * time.Second).Truncate(time.Millisecond)
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
	// Descending order by granted_at.
	if !list[0].GrantedAt.After(list[1].GrantedAt) {
		t.Errorf("order wrong: first=%v second=%v", list[0].GrantedAt, list[1].GrantedAt)
	}
}

func TestSQLiteConsentStore_ListByUserEmptySlice(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	list, err := cs.ListByUser(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	// Must return empty slice, not nil.
	if list == nil {
		t.Fatal("expected empty slice, got nil")
	}
	if len(list) != 0 {
		t.Fatalf("expected 0 grants, got %d", len(list))
	}
}

func TestSQLiteConsentStore_GrantedAtRoundTrip(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	ctx := context.Background()

	// Store nanoseconds but compare at nanosecond precision since
	// we use UnixNano() as the storage unit.
	now := time.Now().UTC()
	// Truncate to nanosecond boundary (effectively a no-op but explicit).
	nowNs := time.Unix(0, now.UnixNano()).UTC()
	_ = cs.RecordConsent(ctx, core.ConsentGrant{
		UserID:    "alice",
		ClientID:  "app1",
		Scopes:    []string{"openid"},
		GrantedAt: nowNs,
	})

	got, err := cs.GetConsent(ctx, "alice", "app1")
	if err != nil {
		t.Fatalf("GetConsent: %v", err)
	}
	if got.GrantedAt.UnixNano() != nowNs.UnixNano() {
		t.Errorf("GrantedAt mismatch: got %v want %v", got.GrantedAt, nowNs)
	}
}

func TestSQLiteConsentStore_SeparatesUserClientPairs(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	ctx := context.Background()

	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app1", Scopes: []string{"openid"}, GrantedAt: time.Now()})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "alice", ClientID: "app2", Scopes: []string{"profile"}, GrantedAt: time.Now()})
	_ = cs.RecordConsent(ctx, core.ConsentGrant{UserID: "bob", ClientID: "app1", Scopes: []string{"email"}, GrantedAt: time.Now()})

	aliceApp1, _ := cs.GetConsent(ctx, "alice", "app1")
	if len(aliceApp1.Scopes) != 1 || aliceApp1.Scopes[0] != "openid" {
		t.Errorf("alice/app1: got %v", aliceApp1.Scopes)
	}
	bobApp1, _ := cs.GetConsent(ctx, "bob", "app1")
	if len(bobApp1.Scopes) != 1 || bobApp1.Scopes[0] != "email" {
		t.Errorf("bob/app1: got %v", bobApp1.Scopes)
	}
}

func TestSQLiteConsentStore_PingWorks(t *testing.T) {
	t.Parallel()
	cs := newTestConsentStore(t)
	if err := cs.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}
