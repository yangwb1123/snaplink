package ssotest

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestRefreshGracePendingBackendsPreserveCompletedResponse(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite", "redis", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			store, advance := newGraceBackend(t, backend, time.Second)
			pending, ok := store.(tokengrant.RefreshGracePendingStore)
			if !ok {
				t.Fatal("stock backend lacks in-flight protection")
			}
			now := time.Now()
			intent := map[string]any{core.KeyRefreshGracePending: true, core.KeyRefreshGraceFamilyID: "family", core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano)}
			pending.PreparePending("original", intent, now)
			intent[core.KeyRefreshGraceFamilyID] = "mutated"
			got, hit := store.Lookup("original", now)
			if !hit || got[core.KeyRefreshGraceFamilyID] != "family" {
				t.Fatalf("missing/aliased pending intent: %v %v", got, hit)
			}
			deadline, err := time.Parse(time.RFC3339Nano, got[core.KeyRefreshGraceDeadline].(string))
			if err != nil || deadline.After(now.Add(2*time.Second)) {
				t.Fatal("serialized pending deadline is not bounded by the store window")
			}
			pending.PreparePending("original", intent, now.Add(time.Millisecond))
			got, hit = store.Lookup("original", now)
			if !hit || got[core.KeyRefreshGraceFamilyID] != "family" {
				t.Fatal("another preparation overwrote live intent")
			}
			advance(2 * time.Second)
			if _, hit := store.Lookup("original", now.Add(2*time.Second)); hit {
				t.Fatal("pending entry extended its window")
			}
			later := now.Add(2 * time.Second)
			pending.PreparePending("original", intent, later)
			ready := map[string]any{core.KeyAccessToken: "issued", core.KeyRefreshToken: "successor", core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano)}
			store.Remember("original", ready, later)
			pending.PreparePending("original", intent, later)
			got, hit = store.Lookup("original", later)
			if !hit || got[core.KeyAccessToken] != "issued" || got[core.KeyRefreshGracePending] == true {
				t.Fatalf("preparation overwrote ready credentials: %v %v", got, hit)
			}
			advance(2 * time.Second)
			if _, hit := store.Lookup("original", later.Add(2*time.Second)); hit {
				t.Fatal("preparation extended completed-response retention")
			}
			delete(intent, core.KeyRefreshGraceDeadline)
			pending.PreparePending("invalid", intent, later)
			if _, hit := store.Lookup("invalid", later); hit {
				t.Fatal("pending intent without grant evidence was stored")
			}
		})
	}
}
