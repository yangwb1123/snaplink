package grpcserver_test

import (
	"context"
	"sync/atomic"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/grpcserver"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// TestClientAdmin_DiscoveryChangeTrigger pins which mutations invalidate
// the discovery cache: Create/Update/Delete change the discovery scope
// union and MUST fire the callback; List/Get/RotateSecret do not affect
// discovery and MUST NOT.
func TestClientAdmin_DiscoveryChangeTrigger(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	store.AddSeed(&sso.Client{ID: "c1", Secret: "s", Active: true, AllowedScopes: []string{"read"}})

	var calls atomic.Int64
	svc := grpcserver.NewClientAdminService(store, nil, func() { calls.Add(1) })
	ctx := context.Background()

	assert := func(t *testing.T, label string, want int64) {
		t.Helper()
		if got := calls.Load(); got != want {
			t.Fatalf("%s: callback fired %d times, want %d", label, got, want)
		}
	}

	// Mutations that change discovery → fire.
	if _, err := svc.Create(ctx, &adminv1.CreateClientRequest{
		Client: &adminv1.Client{Id: "c2", Active: true, AllowedScopes: []string{"write"}},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	assert(t, "after Create", 1)

	if _, err := svc.Update(ctx, &adminv1.UpdateClientRequest{
		Client: &adminv1.Client{Id: "c2", Active: true, AllowedScopes: []string{"write", "admin"}},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	assert(t, "after Update", 2)

	if _, err := svc.Delete(ctx, &adminv1.DeleteClientRequest{Id: "c2"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	assert(t, "after Delete", 3)

	// Reads + secret rotation do not change discovery → no extra fire.
	if _, err := svc.List(ctx, &adminv1.ListClientsRequest{}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if _, err := svc.Get(ctx, &adminv1.GetClientRequest{Id: "c1"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, err := svc.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "c1"}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	assert(t, "after List/Get/RotateSecret", 3)
}

// TestClientAdmin_NilDiscoveryCallbackSafe confirms a nil callback is a
// no-op (single-node / no-bus deployments pass nil).
func TestClientAdmin_NilDiscoveryCallbackSafe(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	svc := grpcserver.NewClientAdminService(store, nil, nil)
	if _, err := svc.Create(context.Background(), &adminv1.CreateClientRequest{
		Client: &adminv1.Client{Id: "c1", Active: true},
	}); err != nil {
		t.Fatalf("create with nil callback: %v", err)
	}
}
