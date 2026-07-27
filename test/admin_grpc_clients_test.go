package ssotest

import (
	"context"
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
)

func TestAdminGRPC_ClientCRUD(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewClientAdminServiceClient(h.Conn)

	// Create
	created, err := svc.Create(h.ctx, &adminv1.CreateClientRequest{
		Client: validClientProto("crud-client", "CRUD Client"),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.GetClient().GetId() != "crud-client" {
		t.Fatalf("got id %q, want crud-client", created.GetClient().GetId())
	}

	// Get
	got, err := svc.Get(h.ctx, &adminv1.GetClientRequest{Id: "crud-client"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GetClient().GetName() != "CRUD Client" {
		t.Fatalf("got name %q, want CRUD Client", got.GetClient().GetName())
	}

	// List
	list, err := svc.List(h.ctx, &adminv1.ListClientsRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetClients()) < 1 {
		t.Fatal("expected at least 1 client")
	}

	// Get unknown → NotFound
	_, err = svc.Get(h.ctx, &adminv1.GetClientRequest{Id: "no-such-client"})
	if err == nil {
		t.Fatal("expected error for unknown client")
	}

	// Delete
	_, err = svc.Delete(h.ctx, &adminv1.DeleteClientRequest{Id: "crud-client"})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify deleted
	_, err = svc.Get(h.ctx, &adminv1.GetClientRequest{Id: "crud-client"})
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestAdminGRPC_ClientRotateSecret(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewClientAdminServiceClient(h.Conn)
	_, err := svc.RotateSecret(h.ctx, &adminv1.RotateSecretRequest{
		Id: "test-client",
	})
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
}

func TestAdminGRPC_ClientAuthDenied(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewClientAdminServiceClient(h.Conn)
	_, err := svc.List(context.Background(), &adminv1.ListClientsRequest{})
	if err == nil {
		t.Fatal("expected PermissionDenied for unauthenticated request")
	}
}

func strPtr(s string) *string { return &s }
