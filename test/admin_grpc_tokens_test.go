package ssotest

import (
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
)

func TestAdminGRPC_TokenCRUD(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewTokenAdminServiceClient(h.Conn)

	_, err := svc.ListSessions(h.ctx, &adminv1.ListSessionsRequest{UserId: "alice"})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}

	_, err = svc.Revoke(h.ctx, &adminv1.RevokeRequest{SessionId: "no-such-session"})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
}
