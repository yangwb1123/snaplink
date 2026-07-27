package memory_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/platform/signingkeys"
	"github.com/yangwb1123/snaplink/platform/signingkeys/memory"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestMemoryRegistry_PublishListSubscribe(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	defer func() { _ = reg.Close() }()
	ctx := context.Background()

	sub, err := reg.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	ann := signingkeys.Announcement{
		ReplicaID:    "r1",
		Keys:         []core.JWK{{Kty: "OKP", Crv: "Ed25519", Kid: "k1", Alg: "EdDSA", X: "abc"}},
		LeaseSeconds: 300,
	}
	if err := reg.Publish(ctx, ann); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	evt := <-sub
	if evt.Type != signingkeys.EventKeysUpserted {
		t.Errorf("event type = %q", evt.Type)
	}
	if evt.Announcement.ReplicaID != "r1" || len(evt.Announcement.Keys) != 1 {
		t.Errorf("event announcement wrong: %+v", evt.Announcement)
	}

	list, err := reg.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ReplicaID != "r1" {
		t.Fatalf("List = %+v", list)
	}

	// List returns defensive copies — mutating one can't corrupt the store.
	list[0].Keys[0].Kid = "tampered"
	list2, _ := reg.List(ctx)
	if list2[0].Keys[0].Kid != "k1" {
		t.Errorf("List returned a shared slice; got kid %q", list2[0].Keys[0].Kid)
	}
}

func TestMemoryRegistry_PublishUpsertsPerReplica(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	defer func() { _ = reg.Close() }()
	ctx := context.Background()

	_ = reg.Publish(ctx, signingkeys.Announcement{ReplicaID: "r1", Keys: []core.JWK{{Kid: "old"}}})
	_ = reg.Publish(ctx, signingkeys.Announcement{ReplicaID: "r1", Keys: []core.JWK{{Kid: "new"}}})
	_ = reg.Publish(ctx, signingkeys.Announcement{ReplicaID: "r2", Keys: []core.JWK{{Kid: "z"}}})

	list, _ := reg.List(ctx)
	if len(list) != 2 {
		t.Fatalf("want 2 replicas, got %d: %+v", len(list), list)
	}
	for _, a := range list {
		if a.ReplicaID == "r1" && (len(a.Keys) != 1 || a.Keys[0].Kid != "new") {
			t.Errorf("r1 not upserted: %+v", a)
		}
	}
}

func TestMemoryRegistry_EmptyReplicaIDRejected(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	defer func() { _ = reg.Close() }()
	if err := reg.Publish(context.Background(), signingkeys.Announcement{}); err == nil {
		t.Fatal("expected error on empty replica_id")
	}
}

func TestMemoryRegistry_CloseClosesSubscribers(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	sub, err := reg.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	_ = reg.Close()
	_ = reg.Close() // idempotent

	if _, ok := <-sub; ok {
		t.Fatal("subscriber channel not closed on Close")
	}
	if err := reg.Publish(context.Background(), signingkeys.Announcement{ReplicaID: "r"}); err == nil {
		t.Fatal("Publish after Close should error")
	}
	if _, err := reg.List(context.Background()); err == nil {
		t.Fatal("List after Close should error")
	}
}

func TestMemoryRegistry_SubscribeCtxCancelCleansUp(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	defer func() { _ = reg.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	sub, err := reg.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()
	// Channel closes when the cleanup goroutine runs.
	for range sub { //nolint:revive // drain until closed
	}
}

var _ signingkeys.Registry = (*memory.Registry)(nil)
