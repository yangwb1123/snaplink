package selfservice

import (
	"net/http"
	"testing"

	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
)

func TestHandleMyDataExport_HappyPath(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1", Email: "u1@example.com"})
	_, _ = d.sessions.Create(t.Context(), "user-1")
	d.dataExporter = &compliance.Exporter{Users: d.users, Sessions: d.sessions}

	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyDataExport(d, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBody(t, rec)
	if resp["subject"] != "user-1" {
		t.Errorf("subject = %v, want user-1", resp["subject"])
	}
	if _, ok := resp["data"]; !ok {
		t.Error("expected a data field in the export bundle")
	}
}

func TestHandleMyDataExport_ExporterNotConfigured(t *testing.T) {
	t.Parallel()
	d := newTestDeps() // dataExporter left nil
	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyDataExport(d, ctx)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}

func TestHandleMyDataExport_ResidencyGateDenies(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	d.dataExporter = &compliance.Exporter{Users: d.users, Sessions: d.sessions}
	d.residencyAccessDeny = "region_not_allowed"
	ctx, rec := newCtx(http.MethodGet, "", "")
	HandleMyDataExport(d, ctx)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != "region_not_allowed" {
		t.Fatalf("error = %v, want region_not_allowed", got)
	}
}

func TestHandleMyAccountErase_ConfirmationRequired(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1"})
	d.accountEraser = &compliance.Eraser{Users: d.users, Sessions: d.sessions}

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"confirm":"someone-else"}`)
	HandleMyAccountErase(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeBody(t, rec)["error"]; got != core.ErrConfirmationRequired {
		t.Fatalf("error = %v, want %s", got, core.ErrConfirmationRequired)
	}
	if _, err := d.users.GetByID(t.Context(), "user-1"); err != nil {
		t.Error("a rejected erase must not delete the account")
	}
}

func TestHandleMyAccountErase_DryRunBypassesConfirmation(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1"})
	d.accountEraser = &compliance.Eraser{Users: d.users, Sessions: d.sessions}

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"dry_run":true}`)
	HandleMyAccountErase(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	resp := decodeBody(t, rec)
	if resp["dry_run"] != true {
		t.Errorf("dry_run = %v, want true", resp["dry_run"])
	}
	if _, err := d.users.GetByID(t.Context(), "user-1"); err != nil {
		t.Error("dry_run must not actually delete the account")
	}
}

func TestHandleMyAccountErase_HappyPathDeletesAccount(t *testing.T) {
	t.Parallel()
	d := newTestDeps()
	_ = d.users.CreateOrUpdate(t.Context(), &core.User{ID: "user-1"})
	d.accountEraser = &compliance.Eraser{Users: d.users, Sessions: d.sessions}

	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"confirm":"user-1"}`)
	HandleMyAccountErase(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if resp := decodeBody(t, rec); resp["user_deleted"] != true {
		t.Errorf("user_deleted = %v, want true", resp["user_deleted"])
	}
	if _, err := d.users.GetByID(t.Context(), "user-1"); err == nil {
		t.Error("account must be deleted after a confirmed erase")
	}
}

func TestHandleMyAccountErase_EraserNotConfigured(t *testing.T) {
	t.Parallel()
	d := newTestDeps() // accountEraser left nil
	ctx, rec := newCtx(http.MethodPost, core.ContentTypeJSON, `{"confirm":"user-1"}`)
	HandleMyAccountErase(d, ctx)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
}
