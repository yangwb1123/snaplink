package configaudit_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// noopLogger satisfies spi.Logger without printing anything.
type noopLogger struct{}

func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}
func (noopLogger) Debug(string, ...any) {}

// handlerDeps is the minimal configaudit.HandlerDeps *sso.Server satisfies
// in production via its own accessor methods (interfaces/sso/accessors.go).
type handlerDeps struct {
	store      configaudit.Store
	applied    map[string]any
	appliedErr error
	running    map[string]any
	runningErr error
}

func (d handlerDeps) ConfigAuditStore() configaudit.Store { return d.store }
func (d handlerDeps) AppliedConfigSnapshot() (map[string]any, error) {
	return d.applied, d.appliedErr
}
func (d handlerDeps) RunningConfigSnapshot(context.Context) (map[string]any, error) {
	return d.running, d.runningErr
}
func (d handlerDeps) SrvLogger() spi.Logger { return noopLogger{} }

func httpCtx(rawQuery string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest("GET", "/api/v1/admin/config/history?"+rawQuery, nil)
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

func httpCtxPOST(body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest("POST", "/api/v1/admin/config/cluster-diff", strings.NewReader(body))
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func TestHandleRunning_RedactsAndReturns200(t *testing.T) {
	d := handlerDeps{running: map[string]any{"db_dsn": "secret-dsn", "name": "sso"}}
	ctx, w := httpCtx("")
	configaudit.HandleRunning(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	running, ok := body[configaudit.KeyRunning].(map[string]any)
	if !ok {
		t.Fatalf("missing %q key: %s", configaudit.KeyRunning, w.Body.String())
	}
	if running["db_dsn"] != "***" {
		t.Errorf("expected running snapshot to be redacted, got %+v", running)
	}
	if running["name"] != "sso" {
		t.Errorf("non-sensitive field must survive, got %+v", running)
	}
}

func TestHandleApplied_RedactsAndReturns200(t *testing.T) {
	d := handlerDeps{applied: map[string]any{"client_secret": "abc"}}
	ctx, w := httpCtx("")
	configaudit.HandleApplied(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	applied := decodeBody(t, w)[configaudit.KeyApplied].(map[string]any)
	if applied["client_secret"] != "***" {
		t.Errorf("expected applied snapshot to be redacted, got %+v", applied)
	}
}

func TestHandleRunning_Unavailable501(t *testing.T) {
	d := handlerDeps{runningErr: configaudit.ErrSnapshotUnavailable}
	ctx, w := httpCtx("")
	configaudit.HandleRunning(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501, body=%s", w.Code, w.Body.String())
	}
	if decodeBody(t, w)[core.KeyError] != configaudit.ErrNotAvailable {
		t.Fatalf("error = %v, want %q", decodeBody(t, w)[core.KeyError], configaudit.ErrNotAvailable)
	}
}

func TestHandleDiff_ReturnsRedactedPatch(t *testing.T) {
	d := handlerDeps{
		applied: map[string]any{"rate_limit": float64(10), "db_dsn": "old-dsn"},
		running: map[string]any{"rate_limit": float64(20), "db_dsn": "new-dsn"},
	}
	ctx, w := httpCtx("")
	configaudit.HandleDiff(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	patch, ok := decodeBody(t, w)[configaudit.KeyPatch].([]any)
	if !ok || len(patch) != 2 {
		t.Fatalf("expected a 2-op patch, got %+v", decodeBody(t, w)[configaudit.KeyPatch])
	}
	for _, raw := range patch {
		op := raw.(map[string]any)
		if op["path"] == "/db_dsn" && op["value"] != "***" {
			t.Errorf("expected /db_dsn value redacted in the diff, got %+v", op)
		}
		if op["path"] == "/rate_limit" && op["value"] != float64(20) {
			t.Errorf("expected /rate_limit value preserved, got %+v", op)
		}
	}
}

func TestHandleDiff_AppliedUnavailable501(t *testing.T) {
	d := handlerDeps{appliedErr: configaudit.ErrSnapshotUnavailable}
	ctx, w := httpCtx("")
	configaudit.HandleDiff(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

func TestHandleClusterDiff_ReturnsRedactedPatchAgainstPeerSnapshot(t *testing.T) {
	d := handlerDeps{running: map[string]any{"rate_limit": float64(20), "db_dsn": "new-dsn"}}
	ctx, w := httpCtxPOST(`{"snapshot":{"rate_limit":10,"db_dsn":"old-dsn"}}`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	patch, ok := decodeBody(t, w)[configaudit.KeyPatch].([]any)
	if !ok || len(patch) != 2 {
		t.Fatalf("expected a 2-op patch, got %+v", decodeBody(t, w)[configaudit.KeyPatch])
	}
	for _, raw := range patch {
		op := raw.(map[string]any)
		if op["path"] == "/db_dsn" && op["value"] != "***" {
			t.Errorf("expected /db_dsn value redacted in the diff, got %+v", op)
		}
		if op["path"] == "/rate_limit" && op["value"] != float64(20) {
			t.Errorf("expected /rate_limit value preserved (this cluster's own), got %+v", op)
		}
	}
}

func TestHandleClusterDiff_EmptySnapshot400(t *testing.T) {
	d := handlerDeps{running: map[string]any{"a": 1}}
	ctx, w := httpCtxPOST(`{}`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestHandleClusterDiff_MalformedBody400(t *testing.T) {
	d := handlerDeps{running: map[string]any{"a": 1}}
	ctx, w := httpCtxPOST(`not-json`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

func TestHandleClusterDiff_RunningUnavailable501(t *testing.T) {
	d := handlerDeps{runningErr: configaudit.ErrSnapshotUnavailable}
	ctx, w := httpCtxPOST(`{"snapshot":{"a":1}}`)
	configaudit.HandleClusterDiff(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501, body=%s", w.Code, w.Body.String())
	}
}

func TestHandleHistory_NoStore501(t *testing.T) {
	d := handlerDeps{}
	ctx, w := httpCtx("")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

func TestHandleHistory_ReturnsEntriesAndCount(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	_ = store.Record(context.Background(), configaudit.Entry{Actor: "alice", Resource: "client", ResourceID: "c1"})
	_ = store.Record(context.Background(), configaudit.Entry{Actor: "bob", Resource: "tenant", ResourceID: "t1"})

	d := handlerDeps{store: store}
	ctx, w := httpCtx("resource=client")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	body := decodeBody(t, w)
	if n, _ := body[configaudit.KeyCount].(float64); int(n) != 1 {
		t.Fatalf("count = %v, want 1", body[configaudit.KeyCount])
	}
}

func TestHandleHistory_BadSince400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	ctx, w := httpCtx("since=not-a-time")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleHistory_BadLimit400(t *testing.T) {
	store := configaudit.NewMemoryStore(0)
	d := handlerDeps{store: store}
	ctx, w := httpCtx("limit=NaN")
	configaudit.HandleHistory(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
