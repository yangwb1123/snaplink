package memory_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenanomaly"
	"github.com/yangwb1123/snaplink/domains/tokenanomaly/memory"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandleAdminSuspicious is exercised against a REAL memory finding store (no
// mocks). Lives in the external memory_test package so it can import both the
// tokenanomaly interface package and its memory implementation without a cycle.

func seedFinding(t *testing.T, s *memory.FindingStore, typ string, sev tokenanomaly.Severity, thumb string) {
	t.Helper()
	if err := s.Add(context.Background(), tokenanomaly.Finding{
		Type: typ, Severity: sev, Thumbprint: thumb,
		FirstSeen: time.Now(), LastSeen: time.Now(),
	}); err != nil {
		t.Fatalf("seed Add: %v", err)
	}
}

func suspiciousCtx(t *testing.T, target string) (*core.Context, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	return core.NewContext(rec, httptest.NewRequest(http.MethodGet, target, nil)), rec
}

type suspiciousResp struct {
	Status   string                 `json:"status"`
	Findings []tokenanomaly.Finding `json:"findings"`
	Total    int                    `json:"total"`
}

func TestHandleAdminSuspicious_ReturnsAndFilters(t *testing.T) {
	s := memory.NewFindingStore()
	seedFinding(t, s, tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1")
	seedFinding(t, s, tokenanomaly.FindingVelocity, tokenanomaly.SeverityCritical, "tp2")

	// Unfiltered: both.
	ctx, rec := suspiciousCtx(t, "/admin/tokens/suspicious")
	tokenanomaly.HandleAdminSuspicious(s, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var out suspiciousResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != core.StatusOK || out.Total != 2 {
		t.Fatalf("got status=%q total=%d, want ok/2", out.Status, out.Total)
	}

	// Filter by severity=critical → only the velocity finding.
	ctx2, rec2 := suspiciousCtx(t, "/admin/tokens/suspicious?severity=critical")
	tokenanomaly.HandleAdminSuspicious(s, spi.NopLogger{}, ctx2)
	var out2 suspiciousResp
	_ = json.Unmarshal(rec2.Body.Bytes(), &out2)
	if out2.Total != 1 || out2.Findings[0].Thumbprint != "tp2" {
		t.Fatalf("severity filter got %+v, want just tp2", out2.Findings)
	}
}

func TestHandleAdminSuspicious_EmptyIsEmptyArray(t *testing.T) {
	ctx, rec := suspiciousCtx(t, "/admin/tokens/suspicious")
	tokenanomaly.HandleAdminSuspicious(memory.NewFindingStore(), spi.NopLogger{}, ctx)
	// The findings field must serialize as [] (not null) so SPAs can iterate.
	if body := rec.Body.String(); !containsJSONEmptyArray(body) {
		t.Fatalf("empty store body = %s, want findings:[]", body)
	}
}

func containsJSONEmptyArray(body string) bool {
	var out map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		return false
	}
	return string(out["findings"]) == "[]"
}
