package caep

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

type streamTestDeps struct {
	store StreamStore
}

func (d *streamTestDeps) StreamStore() StreamStore { return d.store }
func (d *streamTestDeps) ErrorBody(code string) map[string]any {
	return map[string]any{"error": code}
}
func (d *streamTestDeps) ErrorBodyDesc(code, desc string) map[string]any {
	return map[string]any{"error": code, "error_description": desc}
}

func TestHandleCreateStream(t *testing.T) {
	store := NewMemoryStreamStore()
	deps := &streamTestDeps{store: store}
	ctx := newTestContext(t, "POST", "/ssf/streams", `{
		"issuer": "https://sso.test",
		"events": ["https://schemas.openid.net/secevent/caep/token-revocation"],
		"delivery": {"method": "https://schemas.openid.net/secevent/ssf/delivery-method/push", "endpoint": "https://rp.example.com/ssf"}
	}`)

	HandleCreateStream(deps, ctx)

	if ctx.rec.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", ctx.rec.Code, ctx.rec.Body.String())
	}

	var result Stream
	json.NewDecoder(ctx.rec.Body).Decode(&result)
	if result.Issuer != "https://sso.test" {
		t.Errorf("expected issuer, got %q", result.Issuer)
	}
	if result.ID == "" {
		t.Error("expected auto-generated ID")
	}
}

func TestHandleCreateStream_Duplicate(t *testing.T) {
	store := NewMemoryStreamStore()
	ctx := context.Background()
	s := &Stream{Issuer: "https://sso.test", Events: []string{"token-revocation"}}
	store.Create(ctx, s)

	deps := &streamTestDeps{store: store}
	hctx := newTestContext(t, "POST", "/ssf/streams", `{
		"id": "`+s.ID+`",
		"issuer": "https://sso.test"
	}`)

	HandleCreateStream(deps, hctx)
	if hctx.rec.Code != http.StatusConflict {
		t.Errorf("expected 409 for duplicate, got %d", hctx.rec.Code)
	}
}

func TestHandleCreateStream_NoStore(t *testing.T) {
	deps := &streamTestDeps{store: nil}
	ctx := newTestContext(t, "POST", "/ssf/streams", `{}`)

	HandleCreateStream(deps, ctx)
	if ctx.rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 when no store, got %d", ctx.rec.Code)
	}
}

func TestHandleGetStream(t *testing.T) {
	store := NewMemoryStreamStore()
	ctx := context.Background()
	s := &Stream{Issuer: "https://sso.test", Events: []string{"token-revocation"}}
	store.Create(ctx, s)

	deps := &streamTestDeps{store: store}
	hctx := newTestContext(t, "GET", "/ssf/streams/"+s.ID, "")

	HandleGetStream(deps, hctx)
	if hctx.rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", hctx.rec.Code)
	}

	var result Stream
	json.NewDecoder(hctx.rec.Body).Decode(&result)
	if result.ID != s.ID {
		t.Errorf("expected id %q, got %q", s.ID, result.ID)
	}
}

func TestHandleGetStream_NotFound(t *testing.T) {
	store := NewMemoryStreamStore()
	deps := &streamTestDeps{store: store}
	hctx := newTestContext(t, "GET", "/ssf/streams/nonexistent", "")

	HandleGetStream(deps, hctx)
	if hctx.rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", hctx.rec.Code)
	}
}

func TestHandleListStreams(t *testing.T) {
	store := NewMemoryStreamStore()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		store.Create(ctx, &Stream{
			Issuer: "https://sso.test",
			Events: []string{"token-revocation"},
		})
	}

	deps := &streamTestDeps{store: store}
	hctx := newTestContext(t, "GET", "/ssf/streams", "")

	HandleListStreams(deps, hctx)
	if hctx.rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", hctx.rec.Code)
	}

	var result map[string]any
	json.NewDecoder(hctx.rec.Body).Decode(&result)
	streams := result["streams"].([]any)
	if len(streams) != 3 {
		t.Errorf("expected 3 streams, got %d", len(streams))
	}
}

func TestHandleDeleteStream(t *testing.T) {
	store := NewMemoryStreamStore()
	ctx := context.Background()
	s := &Stream{Issuer: "https://sso.test"}
	store.Create(ctx, s)

	deps := &streamTestDeps{store: store}
	hctx := newTestContext(t, "DELETE", "/ssf/streams/"+s.ID, "")

	HandleDeleteStream(deps, hctx)
	if hctx.rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", hctx.rec.Code)
	}

	_, err := store.Get(context.Background(), s.ID)
	if err == nil {
		t.Error("expected stream to be deleted")
	}
}

func TestHandleUpdateStream(t *testing.T) {
	store := NewMemoryStreamStore()
	ctx := context.Background()
	s := &Stream{Issuer: "https://sso.test", Events: []string{"token-revocation"}}
	store.Create(ctx, s)

	updatedJSON := `{"id":"` + s.ID + `","issuer":"https://sso.test","events":["token-revocation","credential-change"]}`
	deps := &streamTestDeps{store: store}
	hctx := newTestContext(t, "PUT", "/ssf/streams/"+s.ID, updatedJSON)

	HandleUpdateStream(deps, hctx)
	if hctx.rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", hctx.rec.Code, hctx.rec.Body.String())
	}

	got, _ := store.Get(context.Background(), s.ID)
	if len(got.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(got.Events))
	}
}

// testContext creates a minimal core.HandlerContext for testing.
func newTestContext(t *testing.T, method, path, body string) *testHandlerContext {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	return &testHandlerContext{
		rec:         rec,
		w:           rec,
		request:     req,
		contextVars: map[string]any{},
		params:      parsePathParams(path),
	}
}

type testHandlerContext struct {
	rec         *httptest.ResponseRecorder
	w           http.ResponseWriter
	request     *http.Request
	contextVars map[string]any
	params      map[string]string
	aborted     bool
}

func (c *testHandlerContext) ResponseWriter() http.ResponseWriter     { return c.w }
func (c *testHandlerContext) Request() *http.Request                  { return c.request }
func (c *testHandlerContext) Get(key string) any                      { return c.contextVars[key] }
func (c *testHandlerContext) Set(key string, v any)                   { c.contextVars[key] = v }
func (c *testHandlerContext) Abort()                                  { c.aborted = true }
func (c *testHandlerContext) Aborted() bool                           { return c.aborted }
func (c *testHandlerContext) Written() bool                           { return false }
func (c *testHandlerContext) SetResponseWriter(w http.ResponseWriter) { c.w = w }
func (c *testHandlerContext) Redirect(code int, target string) {
	http.Redirect(c.w, c.request, target, code)
}
func (c *testHandlerContext) JSON(code int, v any) {
	c.w.WriteHeader(code)
	json.NewEncoder(c.w).Encode(v)
}
func (c *testHandlerContext) Bind(v any) error {
	return json.NewDecoder(c.request.Body).Decode(v)
}
func (c *testHandlerContext) Query(key string) string {
	return c.request.URL.Query().Get(key)
}
func (c *testHandlerContext) Param(key string) string {
	return c.params[key]
}

func parsePathParams(path string) map[string]string {
	params := map[string]string{}
	// Simple path param parser: /ssf/streams/:id
	// If path matches /ssf/streams/some-id, extract id
	if len(path) > 13 && path[:13] == "/ssf/streams/" {
		params["id"] = path[13:]
	}
	return params
}

var _ core.HandlerContext = (*testHandlerContext)(nil)
