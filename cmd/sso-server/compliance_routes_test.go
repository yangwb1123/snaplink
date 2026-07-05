package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

func complianceTestDeps(t *testing.T) (*complianceDeps, *audit.MemorySink) {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	clients := defaultimpl.NewMemoryClientStore()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1", Email: "u1@example.com"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if _, err := sessions.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	sink := audit.NewMemorySink(16)
	return &complianceDeps{
		Users:    users,
		Sessions: sessions,
		Refresh:  refresh,
		Clients:  clients,
		Recorder: audit.New(sink),
	}, sink
}

// TestComplianceExportHandler_IncludesConsentAndMFA proves the admin export
// wiring closes the Eraser/Exporter asymmetry: consent + MFA enrollments,
// which the erase handler already clears, now also appear in the export
// bundle when their stores are wired.
func TestComplianceExportHandler_IncludesConsentAndMFA(t *testing.T) {
	t.Parallel()
	deps, _ := complianceTestDeps(t)
	consentStore := defaultimpl.NewMemoryConsentStore()
	if err := consentStore.RecordConsent(context.Background(), core.ConsentGrant{
		UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}, GrantedAt: time.Now(),
	}); err != nil {
		t.Fatalf("record consent: %v", err)
	}
	mfaStore := defaultimpl.NewMemoryMFAEnrollmentStore()
	mfaStore.AddFactor("u1", core.MFAEnrolledFactor{ID: "f1", Method: "totp", AddedAt: time.Now()})
	deps.Consent = consentStore
	deps.MFAEnrollments = mfaStore

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/users/u1/export", nil)
	complianceExportHandler(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var bundle struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode: %v", err)
	}
	consentData, ok := bundle.Data["consent"].([]any)
	if !ok || len(consentData) != 1 {
		t.Errorf("bundle.data.consent = %#v, want one grant", bundle.Data["consent"])
	}
	mfaData, ok := bundle.Data["mfa_enrollments"].([]any)
	if !ok || len(mfaData) != 1 {
		t.Errorf("bundle.data.mfa_enrollments = %#v, want one factor", bundle.Data["mfa_enrollments"])
	}
}

func TestComplianceExportHandler(t *testing.T) {
	t.Parallel()
	deps, sink := complianceTestDeps(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/users/u1/export", nil)
	complianceExportHandler(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var bundle struct {
		Subject string         `json:"subject"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if bundle.Subject != "u1" {
		t.Errorf("subject = %q, want u1", bundle.Subject)
	}
	if _, ok := bundle.Data["user"]; !ok {
		t.Error("export missing user data")
	}
	assertAudited(t, sink, audit.EventAdminSubjectExported)
}

func TestComplianceEraseHandler(t *testing.T) {
	t.Parallel()
	deps, sink := complianceTestDeps(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/users/u1/erase", nil)
	complianceEraseHandler(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp eraseResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.UserDeleted {
		t.Error("user_deleted = false, want true")
	}
	if _, err := deps.Users.GetByID(context.Background(), "u1"); err == nil {
		t.Error("user still present after erase")
	}
	assertAudited(t, sink, audit.EventAdminSubjectErased)
}

func TestComplianceEraseHandler_DryRun(t *testing.T) {
	t.Parallel()
	deps, _ := complianceTestDeps(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/compliance/users/u1/erase",
		strings.NewReader(`{"dry_run":true}`))
	complianceEraseHandler(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if _, err := deps.Users.GetByID(context.Background(), "u1"); err != nil {
		t.Error("dry-run erase deleted the user")
	}
}

func TestComplianceHandler_InvalidPath(t *testing.T) {
	t.Parallel()
	deps, _ := complianceTestDeps(t)
	rec := httptest.NewRecorder()
	// Nested path (extra segment) must not match a single id.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/users/a/b/export", nil)
	complianceExportHandler(deps)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func assertAudited(t *testing.T, sink *audit.MemorySink, typ audit.EventType) {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{Type: typ})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(events) == 0 {
		t.Errorf("no %q audit event recorded", typ)
		return
	}
	if events[0].Metadata["subject"] != "u1" {
		t.Errorf("audit subject metadata = %q, want u1", events[0].Metadata["subject"])
	}
}
