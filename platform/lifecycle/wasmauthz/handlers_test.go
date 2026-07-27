package wasmauthz_test

// HTTP-handler tests for the WASM authz admin debug Check endpoint. External
// package (wasmauthz_test) mirrors platform/lifecycle/rebac's
// handlers_test.go pattern: a small testDeps satisfies wasmauthz.HandlerDeps
// backed by a real Engine over a real compiled WASM module -- no mocks.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/platform/lifecycle/wasmauthz"
	"github.com/yangwb1123/snaplink/shared/core"
)

type testDeps struct{ eng *wasmauthz.Engine }

func (d testDeps) WASMAuthzEngine() *wasmauthz.Engine { return d.eng }

var _ wasmauthz.HandlerDeps = testDeps{}

type nilEngineDeps struct{}

func (nilEngineDeps) WASMAuthzEngine() *wasmauthz.Engine { return nil }

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

func postCheck(t *testing.T, d wasmauthz.HandlerDeps, req wasmauthz.Request) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader(body)))
	wasmauthz.HandleCheck(d, ctx)
	return rec
}

func TestHandleCheck_Allowed(t *testing.T) {
	t.Parallel()
	d := testDeps{eng: newTestEngine(t, "policy.wasm")}
	rec := postCheck(t, d, wasmauthz.Request{Subject: "alice", Action: "read", Resource: "doc:1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleCheck code=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decodeBody(t, rec)
	if allowed, _ := body[core.KeyWASMAuthzAllowed].(bool); !allowed {
		t.Fatalf("HandleCheck body = %v, want allowed=true", body)
	}
}

func TestHandleCheck_Denied(t *testing.T) {
	t.Parallel()
	d := testDeps{eng: newTestEngine(t, "policy.wasm")}
	rec := postCheck(t, d, wasmauthz.Request{Subject: "bob", Action: "delete"})
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleCheck code=%d", rec.Code)
	}
	body := decodeBody(t, rec)
	if allowed, _ := body[core.KeyWASMAuthzAllowed].(bool); allowed {
		t.Fatalf("HandleCheck body = %v, want allowed=false", body)
	}
}

func TestHandleCheck_MalformedBody(t *testing.T) {
	t.Parallel()
	d := testDeps{eng: newTestEngine(t, "policy.wasm")}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/check", bytes.NewReader([]byte("{not json"))))
	wasmauthz.HandleCheck(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleCheck malformed body code=%d, want 400", rec.Code)
	}
	if decodeBody(t, rec)[core.KeyError] != core.ErrInvalidRequest {
		t.Fatalf("HandleCheck wrong error: %v", rec.Body.String())
	}
}

func TestHandleCheck_NilEngine(t *testing.T) {
	t.Parallel()
	rec := postCheck(t, nilEngineDeps{}, wasmauthz.Request{Subject: "alice", Action: "read"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleCheck nil-engine code=%d, want 500", rec.Code)
	}
	if decodeBody(t, rec)[core.KeyError] != core.ErrWASMAuthzNotConfigured {
		t.Fatalf("HandleCheck nil-engine wrong error: %v", rec.Body.String())
	}
}

func TestHandleCheck_EngineErrorSurfacesAsInternalError(t *testing.T) {
	t.Parallel()
	// trap.wasm's authorize always traps -- Authorize returns an error, and
	// the admin debug endpoint must report it as a 500 (this is a debugging
	// PROBE surfacing the raw failure, not a fabricated {"allowed":false}
	// decision -- see HandleCheck's doc comment).
	d := testDeps{eng: newTestEngine(t, "trap.wasm")}
	rec := postCheck(t, d, wasmauthz.Request{Subject: "alice", Action: "read"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleCheck engine-error code=%d, want 500", rec.Code)
	}
	body := decodeBody(t, rec)
	if body[core.KeyError] != core.ErrInternal {
		t.Fatalf("HandleCheck engine-error wrong error code: %v", rec.Body.String())
	}
	if _, ok := body[core.KeyErrorDescription]; !ok {
		t.Fatalf("HandleCheck engine-error missing description: %v", rec.Body.String())
	}
}
