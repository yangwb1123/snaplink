package rebac_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestHotRuntimeRouteLifecycleAndAudit(t *testing.T) {
	ctx := context.Background()
	store := rebac.NewMemoryStore()
	if err := store.Write(ctx, rebac.Tuple{
		Object: "document:42", Relation: "viewer", Subject: "user:alice",
	}); err != nil {
		t.Fatal(err)
	}
	engine := rebac.NewEngine(store)
	sink := audit.NewMemorySink(16)
	if err := engine.StartHotRuntime(audit.New(sink)); err != nil {
		t.Fatal(err)
	}
	runtime := engine.HotRuntime()
	if runtime == nil || len(runtime.Status()) != 1 || runtime.Status()[0].Generation != 1 {
		t.Fatalf("unexpected initial runtime status: %+v", runtime.Status())
	}
	if err := runtime.Ready(ctx); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	router := core.NewStdRouter()
	deps := runtimeDeps{engine: engine, store: store}
	if !runtime.RegisterCheckRoute(router, deps) {
		t.Fatal("RegisterCheckRoute returned false for StdRouter")
	}
	assertCheckStatus(t, router, http.StatusOK, true)

	if err := runtime.Disable(ctx); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if err := runtime.Ready(ctx); !errors.Is(err, modules.ErrModuleInactive) {
		t.Fatalf("Ready after Disable = %v, want ErrModuleInactive", err)
	}
	assertCheckStatus(t, router, http.StatusNotFound, false)

	if err := runtime.Activate(ctx); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	assertCheckStatus(t, router, http.StatusOK, true)
	events, err := sink.Query(ctx, audit.Query{Type: audit.EventReBACLifecycleTransition})
	if err != nil {
		t.Fatalf("query lifecycle audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected bounded ReBAC lifecycle audit event")
	}
	if events[0].Metadata["module_id"] != "rebac-check" {
		t.Fatalf("module_id metadata = %q", events[0].Metadata["module_id"])
	}
}

func TestHotRuntimeRejectsUnwiredStore(t *testing.T) {
	if err := rebac.NewEngine(nil).StartHotRuntime(nil); !errors.Is(err, rebac.ErrNoStore) {
		t.Fatalf("StartHotRuntime error = %v, want ErrNoStore", err)
	}
}

func assertCheckStatus(t *testing.T, router core.Router, wantStatus int, wantAllowed bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/authz/check?object=document:42&relation=viewer&subject=user:alice", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, wantStatus, rec.Body.String())
	}
	if wantStatus != http.StatusOK {
		return
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got, _ := body[core.KeyRebacAllowed].(bool); got != wantAllowed {
		t.Fatalf("allowed = %v, want %v", got, wantAllowed)
	}
}

type runtimeDeps struct {
	engine *rebac.Engine
	store  rebac.RelationTupleStore
}

func (d runtimeDeps) RebacEngine() *rebac.Engine           { return d.engine }
func (d runtimeDeps) RebacStore() rebac.RelationTupleStore { return d.store }
func (runtimeDeps) ErrorBody(code string) map[string]any {
	return map[string]any{core.KeyError: code}
}
func (runtimeDeps) ErrorBodyDesc(code, desc string) map[string]any {
	return map[string]any{core.KeyError: code, core.KeyErrorDescription: desc}
}

var _ rebac.TupleDeps = runtimeDeps{}
