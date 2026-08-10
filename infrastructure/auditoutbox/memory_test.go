package auditoutbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestMemoryOutboxStore_AppendIsIdempotentPerFact proves a re-append of
// the same fact (same audit event, e.g. a retried record) is a no-op,
// and a different fact under the same idempotency key conflicts.
func TestMemoryOutboxStore_AppendIsIdempotentPerFact(t *testing.T) {
	store := NewMemoryOutboxStore()
	ctx := context.Background()
	fact, err := FactFromAudit(loginFailure("e1", "t1"))
	if err != nil {
		t.Fatalf("fact: %v", err)
	}
	if err := store.Append(ctx, fact); err != nil {
		t.Fatalf("first append: %v", err)
	}
	if err := store.Append(ctx, fact); err != nil {
		t.Fatalf("same-fact re-append must be idempotent: %v", err)
	}
	conflict := *fact
	conflict.PayloadDigest = "different-digest"
	if err := store.Append(ctx, &conflict); !errors.Is(err, commerce.ErrIdempotencyConflict) {
		t.Fatalf("conflicting fact: err=%v want ErrIdempotencyConflict", err)
	}
}

// TestMemoryOutboxStore_AppendFromAuditAppliesGates proves the memory
// path enforces the same fail-closed class/tenant gates as the sqlite
// path.
func TestMemoryOutboxStore_AppendFromAuditAppliesGates(t *testing.T) {
	store := NewMemoryOutboxStore()
	if err := store.AppendFromAudit(context.Background(), &audit.Event{ID: "x", Type: audit.EventLogin}); !errors.Is(err, ErrClassNotPermitted) {
		t.Fatalf("non-login-failure err=%v", err)
	}
	if err := store.AppendFromAudit(context.Background(), loginFailure("e2", "")); !errors.Is(err, ErrFactNotTenantScoped) {
		t.Fatalf("tenant-less err=%v", err)
	}
}

// TestMemoryOutboxStore_RelayLifecycle drives the full claim/complete
// cycle the auditgovernance relay uses: claim leases the fact, complete
// delivers it, a second claim yields nothing (single delivery), and
// fail/dead/replay round-trip.
func TestMemoryOutboxStore_RelayLifecycle(t *testing.T) {
	store := NewMemoryOutboxStore()
	ctx := context.Background()
	now := time.Now().UTC()
	fact, err := FactFromAudit(loginFailure("e3", "t1"))
	if err != nil {
		t.Fatalf("fact: %v", err)
	}
	if err := store.Append(ctx, fact); err != nil {
		t.Fatalf("append: %v", err)
	}

	claimed, err := store.ClaimOutbox(ctx, "relay-1", now, time.Minute, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(claimed) != 1 || claimed[0].ID != "e3" {
		t.Fatalf("claimed: %+v", claimed)
	}
	if claimed[0].Status != commerce.OutboxLeased || claimed[0].LeaseOwner != "relay-1" {
		t.Errorf("lease not applied: %+v", claimed[0])
	}
	if err := store.CompleteOutbox(ctx, "e3", "relay-1", now); err != nil {
		t.Fatalf("complete: %v", err)
	}
	again, err := store.ClaimOutbox(ctx, "relay-1", now.Add(time.Hour), time.Minute, 10)
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("delivered fact re-claimed: %+v", again)
	}

	// Fail path: retry then dead.
	store2 := NewMemoryOutboxStore()
	fact2, _ := FactFromAudit(loginFailure("e4", "t1"))
	_ = store2.Append(ctx, fact2)
	_, _ = store2.ClaimOutbox(ctx, "relay-2", now, time.Minute, 10)
	_ = store2.FailOutbox(ctx, "e4", "relay-2", "transport", now, now.Add(time.Second), 1)
	dead, err := store2.ListDeadOutbox(ctx, 10)
	if err != nil || len(dead) != 1 || dead[0].Status != commerce.OutboxDead {
		t.Fatalf("dead list: %v %+v", err, dead)
	}
	if err := store2.ReplayOutbox(ctx, "e4", now); err != nil {
		t.Fatalf("replay: %v", err)
	}
	reclaimed, _ := store2.ClaimOutbox(ctx, "relay-2", now, time.Minute, 10)
	if len(reclaimed) != 1 {
		t.Errorf("replayed fact not reclaimable: %+v", reclaimed)
	}
}

// TestMemoryOutboxStore_PendingSurfacesDurability proves the durability
// assertion surface: a committed fact is observable as pending BEFORE
// any relay runs.
func TestMemoryOutboxStore_PendingSurfacesDurability(t *testing.T) {
	store := NewMemoryOutboxStore()
	_ = store.AppendFromAudit(context.Background(), loginFailure("e5", "t1"))
	pending, err := store.Pending(context.Background())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending: %v %+v", err, pending)
	}
	if pending[0].Payload[PayloadKeyAuditHash] != "hash-e5" {
		t.Errorf("pending fact lost audit linkage: %+v", pending[0])
	}
}
