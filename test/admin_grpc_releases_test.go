package ssotest

import (
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
)

func TestAdminGRPC_ReleaseCRUD(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewReleaseAdminServiceClient(h.Conn)

	created, err := svc.Register(h.ctx, &adminv1.RegisterReleaseRequest{
		Release: validReleaseProto("release-1", 1),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if created.GetRelease().GetId() != "release-1" {
		t.Fatalf("got id %q", created.GetRelease().GetId())
	}

	list, err := svc.List(h.ctx, &adminv1.ListReleasesRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.GetItems()) < 1 {
		t.Fatal("expected at least 1 release")
	}

	pinned, err := svc.Pin(h.ctx, &adminv1.PinReleaseRequest{Id: "release-1"})
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	_ = pinned
}

func TestAdminGRPC_ReleaseGetCurrent(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewReleaseAdminServiceClient(h.Conn)
	_, err := svc.GetCurrent(h.ctx, &adminv1.GetCurrentReleaseRequest{})
	if err != nil {
		t.Fatalf("GetCurrent: %v", err)
	}
}
