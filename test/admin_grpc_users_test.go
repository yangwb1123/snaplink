package ssotest

import (
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
)

func TestAdminGRPC_UserCRUD(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewUserAdminServiceClient(h.Conn)

	created, err := svc.Create(h.ctx, &adminv1.CreateUserRequest{
		User: &adminv1.User{
			Id:         "new-user",
			Attributes: map[string]string{"email": "new-user@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.GetUser().GetId() != "new-user" {
		t.Fatalf("got id %q, want new-user", created.GetUser().GetId())
	}

	got, err := svc.Get(h.ctx, &adminv1.GetUserRequest{Id: "new-user"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.GetUser().GetAttributes()["email"] != "new-user@example.com" {
		t.Fatalf("got email %q", got.GetUser().GetAttributes()["email"])
	}

	list, err := svc.List(h.ctx, &adminv1.ListUsersRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetUsers()) < 1 {
		t.Fatal("expected at least 1 user")
	}

	_, err = svc.Get(h.ctx, &adminv1.GetUserRequest{Id: "no-such-user"})
	if err == nil {
		t.Fatal("expected error for unknown user")
	}

	_, err = svc.Delete(h.ctx, &adminv1.DeleteUserRequest{Id: "new-user"})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = svc.Get(h.ctx, &adminv1.GetUserRequest{Id: "new-user"})
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestAdminGRPC_UserListSessions(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewUserAdminServiceClient(h.Conn)
	_, err := svc.ListUserSessions(h.ctx, &adminv1.ListUserSessionsRequest{Id: "alice"})
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
}
