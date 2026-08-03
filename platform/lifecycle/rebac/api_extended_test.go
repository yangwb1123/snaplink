package rebac

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testDeps struct {
	store  RelationTupleStore
	engine *Engine
}

func (d *testDeps) RebacStore() RelationTupleStore { return d.store }
func (d *testDeps) RebacEngine() *Engine           { return d.engine }
func (d *testDeps) ErrorBody(code string) map[string]any {
	return map[string]any{"error": code}
}
func (d *testDeps) ErrorBodyDesc(code, desc string) map[string]any {
	return map[string]any{"error": code, "error_description": desc}
}

type rebacTestCtx struct {
	rec  *httptest.ResponseRecorder
	w    http.ResponseWriter
	req  *http.Request
	vars map[string]any
}

func (c *rebacTestCtx) ResponseWriter() http.ResponseWriter     { return c.w }
func (c *rebacTestCtx) Request() *http.Request                  { return c.req }
func (c *rebacTestCtx) Get(key string) any                      { return c.vars[key] }
func (c *rebacTestCtx) Set(key string, v any)                   { c.vars[key] = v }
func (c *rebacTestCtx) Abort()                                  {}
func (c *rebacTestCtx) Aborted() bool                           { return false }
func (c *rebacTestCtx) Written() bool                           { return false }
func (c *rebacTestCtx) SetResponseWriter(w http.ResponseWriter) { c.w = w }
func (c *rebacTestCtx) Redirect(code int, url string) {
	http.Redirect(c.w, c.req, url, code)
}
func (c *rebacTestCtx) JSON(code int, v any) {
	c.w.WriteHeader(code)
	json.NewEncoder(c.w).Encode(v)
}
func (c *rebacTestCtx) Bind(v any) error {
	return json.NewDecoder(c.req.Body).Decode(v)
}
func (c *rebacTestCtx) Query(key string) string { return c.req.URL.Query().Get(key) }
func (c *rebacTestCtx) Param(key string) string { return "" }

func newRebacCtx(t *testing.T, method, path, body string) *rebacTestCtx {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	return &rebacTestCtx{
		rec:  rec,
		w:    rec,
		req:  req,
		vars: map[string]any{},
	}
}

func TestHandleBatchWriteTuples(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	deps := &testDeps{store: store}

	body := `{"writes":[
		{"object":"doc:1","relation":"viewer","subject":"user:alice"},
		{"object":"doc:1","relation":"editor","subject":"user:bob"}
	]}`

	hctx := newRebacCtx(t, "POST", "/authz/tuples/batch", body)
	HandleBatchWriteTuples(deps, hctx)

	if hctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", hctx.rec.Code, hctx.rec.Body.String())
	}

	// Verify tuples were written
	tuples, _ := store.Read(ctx, TupleFilter{Object: "doc:1"})
	if len(tuples) != 2 {
		t.Errorf("expected 2 tuples, got %d", len(tuples))
	}

	var result map[string]any
	json.NewDecoder(hctx.rec.Body).Decode(&result)
	if result["written"].(float64) != 2 {
		t.Errorf("expected 2 written, got %v", result["written"])
	}
}

func TestHandleBatchWriteTuples_WithDeletes(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	store.Write(ctx, Tuple{Object: "doc:1", Relation: "viewer", Subject: "user:alice"})

	deps := &testDeps{store: store}
	body := `{"deletes":[
		{"object":"doc:1","relation":"viewer","subject":"user:alice"}
	],"writes":[
		{"object":"doc:1","relation":"viewer","subject":"user:bob"}
	]}`

	hctx := newRebacCtx(t, "POST", "/authz/tuples/batch", body)
	HandleBatchWriteTuples(deps, hctx)

	if hctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", hctx.rec.Code)
	}

	tuples, _ := store.Read(ctx, TupleFilter{Object: "doc:1"})
	if len(tuples) != 1 {
		t.Errorf("expected 1 remaining tuple, got %d", len(tuples))
	}
	if tuples[0].Subject != "user:bob" {
		t.Errorf("expected subject 'user:bob', got %q", tuples[0].Subject)
	}
}

func TestHandleBatchWriteTuples_NoStore(t *testing.T) {
	deps := &testDeps{store: nil}
	hctx := newRebacCtx(t, "POST", "/authz/tuples/batch", `{}`)
	HandleBatchWriteTuples(deps, hctx)
	if hctx.rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", hctx.rec.Code)
	}
}

func TestHandleBatchWriteTuples_InvalidJSON(t *testing.T) {
	store := NewMemoryStore()
	deps := &testDeps{store: store}
	hctx := newRebacCtx(t, "POST", "/authz/tuples/batch", `{invalid}`)
	HandleBatchWriteTuples(deps, hctx)
	if hctx.rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", hctx.rec.Code)
	}
}

func TestHandleBatchWriteTuples_IsAtomicAndReportsStableItems(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	_ = store.Write(ctx, Tuple{Object: "doc:existing", Relation: "viewer", Subject: "user:alice"})
	deps := &testDeps{store: store}
	body := `{"idempotency_key":"batch-42","writes":[
		{"object":"doc:new","relation":"viewer","subject":"user:bob"},
		{"object":"invalid","relation":"viewer","subject":"user:carol"}
	]}`

	first := newRebacCtx(t, "POST", "/authz/tuples/batch", body)
	HandleBatchWriteTuples(deps, first)
	if first.rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", first.rec.Code, first.rec.Body.String())
	}
	tuples, _ := store.Read(ctx, TupleFilter{})
	if len(tuples) != 1 || tuples[0].Object != "doc:existing" {
		t.Fatalf("invalid batch partially mutated graph: %+v", tuples)
	}
	var response struct {
		Items []batchTupleResult `json:"items"`
	}
	if err := json.NewDecoder(first.rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(response.Items) != 2 ||
		response.Items[0].IdempotencyKey != "batch-42:write:0" ||
		response.Items[1].IdempotencyKey != "batch-42:write:1" {
		t.Fatalf("unstable per-item results: %+v", response.Items)
	}
	for _, item := range response.Items {
		if item.Status != "not_applied" {
			t.Fatalf("item unexpectedly applied: %+v", item)
		}
	}
}

func TestHandleReverseExpand(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	store.Write(ctx, Tuple{Object: "doc:1", Relation: "viewer", Subject: "user:alice"})
	store.Write(ctx, Tuple{Object: "doc:2", Relation: "editor", Subject: "user:alice"})
	store.Write(ctx, Tuple{Object: "doc:1", Relation: "viewer", Subject: "user:bob"})

	deps := &testDeps{store: store}
	hctx := newRebacCtx(t, "GET", "/authz/graph?subject=user:alice", "")
	HandleReverseExpand(deps, hctx)

	if hctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", hctx.rec.Code)
	}

	var result map[string]any
	json.NewDecoder(hctx.rec.Body).Decode(&result)
	if result["subject"] != "user:alice" {
		t.Errorf("expected subject 'user:alice', got %v", result["subject"])
	}
	edges := result["edges"].([]any)
	if len(edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(edges))
	}
}

func TestHandleReverseExpand_EmptySubject(t *testing.T) {
	store := NewMemoryStore()
	deps := &testDeps{store: store}
	hctx := newRebacCtx(t, "GET", "/authz/graph", "")
	HandleReverseExpand(deps, hctx)
	if hctx.rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", hctx.rec.Code)
	}
}

func TestHandleReverseExpand_NoStore(t *testing.T) {
	deps := &testDeps{store: nil}
	hctx := newRebacCtx(t, "GET", "/authz/graph?subject=user:alice", "")
	HandleReverseExpand(deps, hctx)
	if hctx.rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", hctx.rec.Code)
	}
}

func TestHandleReverseExpand_NoResults(t *testing.T) {
	store := NewMemoryStore()
	deps := &testDeps{store: store}
	hctx := newRebacCtx(t, "GET", "/authz/graph?subject=user:unknown", "")
	HandleReverseExpand(deps, hctx)
	if hctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", hctx.rec.Code)
	}
	var result map[string]any
	json.NewDecoder(hctx.rec.Body).Decode(&result)
	edges := result["edges"].([]any)
	if len(edges) != 0 {
		t.Errorf("expected 0 edges for unknown user, got %d", len(edges))
	}
}
