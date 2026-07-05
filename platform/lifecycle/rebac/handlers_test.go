package rebac_test

// HTTP-handler tests for the ReBAC admin debug Check endpoint. External
// package (rebac_test) mirrors platform/lifecycle/webhook's
// handlers_test.go pattern: a small testDeps satisfies rebac.HandlerDeps
// backed by a real Engine over a real MemoryStore — no mocks.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/platform/lifecycle/rebac"
	"github.com/snaplink/sso/shared/core"
)

type testDeps struct{ eng *rebac.Engine }

func (d testDeps) RebacEngine() *rebac.Engine { return d.eng }

var _ rebac.HandlerDeps = testDeps{}

type nilEngineDeps struct{}

func (nilEngineDeps) RebacEngine() *rebac.Engine { return nil }

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestHandleCheck_Allowed(t *testing.T) {
	t.Parallel()
	store := rebac.NewMemoryStore()
	if err := store.Write(context.Background(), rebac.Tuple{Object: "document:42", Relation: "viewer", Subject: "user:alice"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d := testDeps{eng: rebac.NewEngine(store)}

	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check?object=document:42&relation=viewer&subject=user:alice", nil))
	rebac.HandleCheck(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleCheck code=%d body=%s", rec.Code, rec.Body.String())
	}
	body := decode(t, rec)
	if allowed, _ := body[core.KeyRebacAllowed].(bool); !allowed {
		t.Fatalf("HandleCheck body = %v, want allowed=true", body)
	}
}

func TestHandleCheck_Denied(t *testing.T) {
	t.Parallel()
	d := testDeps{eng: rebac.NewEngine(rebac.NewMemoryStore())}

	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check?object=document:42&relation=viewer&subject=user:bob", nil))
	rebac.HandleCheck(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleCheck code=%d", rec.Code)
	}
	body := decode(t, rec)
	if allowed, _ := body[core.KeyRebacAllowed].(bool); allowed {
		t.Fatalf("HandleCheck body = %v, want allowed=false", body)
	}
}

func TestHandleCheck_MissingParams(t *testing.T) {
	t.Parallel()
	d := testDeps{eng: rebac.NewEngine(rebac.NewMemoryStore())}

	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check?object=document:42&relation=viewer", nil))
	rebac.HandleCheck(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleCheck missing subject code=%d, want 400", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrInvalidRequest {
		t.Fatalf("HandleCheck wrong error: %v", rec.Body.String())
	}
}

func TestHandleCheck_NilEngine(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/check?object=document:42&relation=viewer&subject=user:alice", nil))
	rebac.HandleCheck(nilEngineDeps{}, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleCheck nil-engine code=%d, want 500", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrRebacNotConfigured {
		t.Fatalf("HandleCheck nil-engine wrong error: %v", rec.Body.String())
	}
}
