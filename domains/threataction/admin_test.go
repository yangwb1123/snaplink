package threataction_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/domains/threataction/memory"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandleAdminPutPolicy/HandleAdminDeletePolicy are exercised against a REAL
// memory.ThreatPolicyStore (no mocks, per repo convention) in this external
// _test package so it can import both the threataction interface package
// and its memory implementation without a cycle.

// nameParamCtx layers a :name route param onto a core.Context -- StdRouter
// would inject it via path matching (extractParams stripping the leading
// ":") in production; tests supply it directly. Mirrors gcParamCtx /
// bgParamCtx in interfaces/admin's governance_test.go / break_glass_test.go.
type nameParamCtx struct {
	*core.Context
	name string
}

func (p nameParamCtx) Param(key string) string {
	if key == "name" {
		return p.name
	}
	return p.Context.Param(key)
}

func putCtx(name, body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodPut, "/api/v1/admin/threat-policies/"+name, bytes.NewBufferString(body))
	r.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	w := httptest.NewRecorder()
	return nameParamCtx{Context: core.NewContext(w, r), name: name}, w
}

func deleteCtx(name string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/threat-policies/"+name, nil)
	w := httptest.NewRecorder()
	return nameParamCtx{Context: core.NewContext(w, r), name: name}, w
}

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var out map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode error body: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

func TestHandleAdminPutPolicy_ValidPolicyAccepted(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	body := `{"enabled":true,"type":"impossible_travel","severity":"critical","action":"suspend",
		"rate_limit":{"per_window":"1h","max":3},
		"conditions":{"key":"distance_km","operator":"gt","value":"1000"}}`
	ctx, rec := putCtx("strict", body)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	got, err := store.Get(ctx.Request().Context(), "strict")
	if err != nil {
		t.Fatalf("Get after Put: %v", err)
	}
	if got.Name != "strict" || got.Action != threataction.ActionSuspend {
		t.Fatalf("stored policy = %+v, want name=strict action=suspend", got)
	}
}

func TestHandleAdminPutPolicy_EmptyActionAccepted(t *testing.T) {
	// Empty Action is treated identically to ActionNoop by the composite
	// executor (registry.go's Execute: act == ActionNoop || act == "" both
	// short-circuit to "policy action is noop") -- so a PUT that omits
	// action must be accepted, not rejected, mirroring a YAML-seeded
	// catch-all/observation policy.
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("observe-only", `{"enabled":true,"type":"new_device"}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAdminPutPolicy_MalformedJSONRejected(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("bad", `{not-json`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := decodeErrorBody(t, rec)[core.KeyError]; got != core.ErrInvalidRequest {
		t.Errorf("error = %q, want %q", got, core.ErrInvalidRequest)
	}
}

func TestHandleAdminPutPolicy_UnknownActionRejected(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("bogus-action", `{"enabled":true,"action":"delete_everything"}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	body := decodeErrorBody(t, rec)
	if body[core.KeyError] != core.ErrInvalidPolicy {
		t.Errorf("error = %q, want %q", body[core.KeyError], core.ErrInvalidPolicy)
	}
	if body[core.KeyErrorDescription] == "" {
		t.Error("expected a non-empty error_description naming the violated field")
	}
	if _, err := store.Get(ctx.Request().Context(), "bogus-action"); err != threataction.ErrPolicyNotFound {
		t.Error("rejected policy must not be persisted")
	}
}

func TestHandleAdminPutPolicy_NegativeRateLimitMaxRejected(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("neg-max", `{"enabled":true,"action":"notify","rate_limit":{"per_window":"1h","max":-1}}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := decodeErrorBody(t, rec)[core.KeyError]; got != core.ErrInvalidPolicy {
		t.Errorf("error = %q, want %q", got, core.ErrInvalidPolicy)
	}
}

func TestHandleAdminPutPolicy_NegativeRateLimitPerWindowRejected(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("neg-window", `{"enabled":true,"action":"notify","rate_limit":{"per_window":"-1h","max":3}}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := decodeErrorBody(t, rec)[core.KeyError]; got != core.ErrInvalidPolicy {
		t.Errorf("error = %q, want %q", got, core.ErrInvalidPolicy)
	}
}

func TestHandleAdminPutPolicy_ZeroRateLimitMaxAccepted(t *testing.T) {
	// 0 is the established "disabled" idiom (registry.go's allow(): rl.Max
	// <= 0 -> unlimited), not an error -- only a negative Max is a mistake.
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("zero-max", `{"enabled":true,"action":"notify","rate_limit":{"per_window":"1h","max":0}}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAdminPutPolicy_BadOperatorRejected(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("bad-operator", `{"enabled":true,"action":"notify","conditions":{"key":"distance_km","operator":"between","value":"1"}}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := decodeErrorBody(t, rec)[core.KeyError]; got != core.ErrInvalidPolicy {
		t.Errorf("error = %q, want %q", got, core.ErrInvalidPolicy)
	}
}

func TestHandleAdminPutPolicy_BadOperatorIgnoredWhenKeyEmpty(t *testing.T) {
	// An empty Conditions.Key is already "unconditional" per
	// ThreatConditions.Match, so a garbage Operator alongside it is inert
	// and must not be rejected.
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("no-key", `{"enabled":true,"action":"notify","conditions":{"operator":"between","value":"1"}}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleAdminPutPolicy_UsesNameRouteParamNotBody(t *testing.T) {
	// Regression guard for the :name / name route-param key mismatch: the
	// path segment must win over the JSON body's own (ignored) "name" field,
	// AND actually be threaded through as the stored key -- proving
	// ctx.Param(paramPolicyName) really resolves against the route param
	// StdRouter's extractParams sets (bare "name", colon stripped), not a
	// literal ":name" key that would always read back "".
	store := memory.NewThreatPolicyStore()
	ctx, rec := putCtx("routed-name", `{"enabled":true,"action":"notify"}`)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if _, err := store.Get(ctx.Request().Context(), "routed-name"); err != nil {
		t.Fatalf("policy must be stored under the route param name: %v", err)
	}
}

func TestHandleAdminDeletePolicy_NotFound(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	ctx, rec := deleteCtx("does-not-exist")
	threataction.HandleAdminDeletePolicy(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
	if got := decodeErrorBody(t, rec)[core.KeyError]; got != core.ErrNotFound {
		t.Errorf("error = %q, want %q", got, core.ErrNotFound)
	}
}

func TestHandleAdminDeletePolicy_Success(t *testing.T) {
	store := memory.NewThreatPolicyStore()
	putBody := `{"enabled":true,"action":"notify"}`
	putReqCtx, _ := putCtx("to-delete", putBody)
	threataction.HandleAdminPutPolicy(store, spi.NopLogger{}, putReqCtx)

	ctx, rec := deleteCtx("to-delete")
	threataction.HandleAdminDeletePolicy(store, spi.NopLogger{}, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := decodeErrorBody(t, rec)[core.KeyStatus]; got != core.StatusOK {
		t.Errorf("status field = %q, want %q", got, core.StatusOK)
	}
	if _, err := store.Get(ctx.Request().Context(), "to-delete"); err != threataction.ErrPolicyNotFound {
		t.Error("policy should be gone after delete")
	}
}
