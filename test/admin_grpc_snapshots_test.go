package ssotest

import (
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
)

func TestAdminGRPC_SnapshotExport(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewSnapshotAdminServiceClient(h.Conn)

	exported, err := svc.Export(h.ctx, &adminv1.ExportSnapshotRequest{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if exported.GetStoredAs() == "" {
		t.Fatal("expected non-empty snapshot data")
	}

	list, err := svc.List(h.ctx, &adminv1.ListSnapshotsRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	_ = list
}
