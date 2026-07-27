package memory

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// This file exercises tokenpolicy.HandleAdminPolicies against a REAL memory
// Store (no mocks, per AGENTS.md §0.5). It lives beside the memory impl rather
// than in domains/tokenpolicy itself because tokenpolicy/memory already depends
// on tokenpolicy one-way; the reverse import from a domains/tokenpolicy test
// would be a cycle (mirrors tokenusage/memory/admin_test.go).

func newAdminCtx(t *testing.T) (*core.Context, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/token-policies", nil)
	return core.NewContext(rec, req), rec
}

// TestHandleAdminPolicies_ListsActivePolicies proves the governance read
// returns the active set through the JSON envelope.
func TestHandleAdminPolicies_ListsActivePolicies(t *testing.T) {
	t.Parallel()
	store := New(
		tokenpolicy.Policy{Name: "short-ttl", ClientID: "c1", MaxTTL: 5 * time.Minute},
		tokenpolicy.Policy{Name: "no-admin-openid", BlockScopeCombos: [][]string{{"admin:*", "openid"}}},
	)
	ctx, rec := newAdminCtx(t)
	tokenpolicy.HandleAdminPolicies(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status   string               `json:"status"`
		Policies []tokenpolicy.Policy `json:"policies"`
		Total    int                  `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != core.StatusOK {
		t.Errorf("status field = %q, want %q", out.Status, core.StatusOK)
	}
	if out.Total != 2 || len(out.Policies) != 2 {
		t.Fatalf("total/len = %d/%d, want 2/2", out.Total, len(out.Policies))
	}
	if out.Policies[0].Name != "short-ttl" || out.Policies[0].MaxTTL != 5*time.Minute {
		t.Errorf("policy[0] = %+v", out.Policies[0])
	}
}

// TestHandleAdminPolicies_EmptyIsEmptyArrayNotNull guards the JSON contract: an
// admin dashboard parsing `policies` must always see an array, never `null`.
func TestHandleAdminPolicies_EmptyIsEmptyArrayNotNull(t *testing.T) {
	t.Parallel()
	ctx, rec := newAdminCtx(t)
	tokenpolicy.HandleAdminPolicies(New(), spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr, ok := out["policies"].([]any)
	if !ok || len(arr) != 0 {
		t.Fatalf("policies = %#v, want a literal empty array", out["policies"])
	}
}
