package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oidc/bcl"
)

func TestBackchannelFailureStorePersistsAndScopesTenants(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	store := NewBackchannelFailureStore(rdb)
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		_, err := store.Enqueue(context.Background(), bcl.Failure{
			ID: tenantID, TenantID: tenantID, ClientID: "client", Subject: "local",
			TokenSubject: "pairwise", URI: "https://rp.example/bcl", Attempts: 3,
			FirstFailedAt: now, LastFailedAt: now, NextAttemptAt: now,
		})
		if err != nil {
			t.Fatalf("enqueue %s: %v", tenantID, err)
		}
	}
	reopened := NewBackchannelFailureStore(rdb)
	entries, err := reopened.List(context.Background(), bcl.Filter{TenantID: "tenant-a", Limit: 10})
	if err != nil || len(entries) != 1 || entries[0].ID != "tenant-a" {
		t.Fatalf("tenant list = %+v, %v", entries, err)
	}
	all, err := reopened.List(context.Background(), bcl.Filter{Limit: 10})
	if err != nil || len(all) != 2 {
		t.Fatalf("global list = %+v, %v", all, err)
	}
}

func TestBackchannelFailureStoreLeaseIsSharedAcrossReplicas(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	first := NewBackchannelFailureStore(rdb)
	second := NewBackchannelFailureStore(rdb)
	now := time.Now().UTC()
	f, err := first.Enqueue(context.Background(), bcl.Failure{
		ID: "shared", TenantID: "tenant", ClientID: "client", Attempts: 3,
		FirstFailedAt: now, LastFailedAt: now, NextAttemptAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, token, err := first.Claim(context.Background(), f.ID, "tenant", time.Minute)
	if err != nil || token == "" {
		t.Fatalf("claim = %+v, %q, %v", claimed, token, err)
	}
	if _, _, err := second.Claim(context.Background(), f.ID, "tenant", time.Minute); !errors.Is(err, bcl.ErrLeaseUnavailable) {
		t.Fatalf("second replica claim = %v", err)
	}
	if err := second.Ack(context.Background(), f, "stale"); !errors.Is(err, bcl.ErrLeaseUnavailable) {
		t.Fatalf("stale ack = %v", err)
	}
	if err := first.Ack(context.Background(), f, token); err != nil {
		t.Fatalf("owner ack: %v", err)
	}
	left, _ := second.List(context.Background(), bcl.Filter{TenantID: "tenant", Limit: 10})
	if len(left) != 0 {
		t.Fatalf("acked failure remains: %+v", left)
	}
}

func TestBackchannelFailureStoreReschedulesAndAccumulatesAttempts(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	store := NewBackchannelFailureStore(rdb)
	now := time.Now().UTC().Truncate(time.Millisecond)
	f, _ := store.Enqueue(context.Background(), bcl.Failure{ID: "retry", Attempts: 3,
		FirstFailedAt: now, LastFailedAt: now, NextAttemptAt: now})
	claimed, token, err := store.Claim(context.Background(), f.ID, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claimed.Attempts = 6
	claimed.LastError = "still down"
	claimed.LastFailedAt = now.Add(time.Second)
	claimed.NextAttemptAt = now.Add(time.Minute)
	if err := store.Reschedule(context.Background(), claimed, token); err != nil {
		t.Fatalf("reschedule: %v", err)
	}
	updated, _ := store.List(context.Background(), bcl.Filter{Limit: 10})
	if len(updated) != 1 || updated[0].Attempts != 6 || updated[0].LastError != "still down" {
		t.Fatalf("updated failure = %+v", updated)
	}
	merged, err := store.Enqueue(context.Background(), bcl.Failure{ID: "retry", Attempts: 3,
		FirstFailedAt: now.Add(time.Hour), LastFailedAt: now.Add(time.Hour), NextAttemptAt: now})
	if err != nil || merged.Attempts != 9 {
		t.Fatalf("merged attempts = %+v, %v", merged, err)
	}
}
