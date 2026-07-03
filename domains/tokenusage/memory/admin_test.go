package memory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenusage"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// This file exercises tokenusage.HandleAdminUsage against a REAL memory
// Store (no mocks, per AGENTS.md §0.5) — it lives beside the memory
// implementation rather than in domains/tokenusage itself because
// tokenusage/memory already depends on tokenusage one-way; the reverse
// import from a domains/tokenusage test would be a cycle.

func newAdminCtx(t *testing.T, target string) (*core.Context, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	return core.NewContext(rec, req), rec
}

// seedBase is the fixed origin every seeded event's minute offset is
// relative to, matching the since/until literals the window test asserts.
var seedBase = time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)

func seedStore(t *testing.T, s *Store, clientID string, kind tokenusage.Kind, endpoint tokenusage.Endpoint, minuteOffset int) {
	t.Helper()
	if err := s.Record(context.Background(), tokenusage.Event{
		ClientID: clientID,
		Kind:     kind,
		Endpoint: endpoint,
		At:       seedBase.Add(time.Duration(minuteOffset) * time.Minute),
	}); err != nil {
		t.Fatalf("seed Record: %v", err)
	}
}

// TestHandleAdminUsage_ReturnsAggregatedBuckets proves the happy path: a
// pre-seeded store's buckets come back through the JSON envelope unfiltered
// when no query parameters are given.
func TestHandleAdminUsage_ReturnsAggregatedBuckets(t *testing.T) {
	store := New()
	seedStore(t, store, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, 0)
	seedStore(t, store, "client-b", tokenusage.KindRefresh, tokenusage.EndpointIntrospect, 1)

	ctx, rec := newAdminCtx(t, "/admin/tokens/usage")
	tokenusage.HandleAdminUsage(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status  string              `json:"status"`
		Buckets []tokenusage.Bucket `json:"buckets"`
		Total   int                 `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != core.StatusOK {
		t.Errorf("status field = %q, want %q", out.Status, core.StatusOK)
	}
	if out.Total != 2 || len(out.Buckets) != 2 {
		t.Fatalf("total/len = %d/%d, want 2/2: %+v", out.Total, len(out.Buckets), out.Buckets)
	}
}

// TestHandleAdminUsage_FiltersByClientID proves the client_id query
// parameter narrows the result set to just that client's buckets.
func TestHandleAdminUsage_FiltersByClientID(t *testing.T) {
	store := New()
	seedStore(t, store, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, 0)
	seedStore(t, store, "client-b", tokenusage.KindAccess, tokenusage.EndpointToken, 0)

	ctx, rec := newAdminCtx(t, "/admin/tokens/usage?client_id=client-a")
	tokenusage.HandleAdminUsage(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out struct {
		Buckets []tokenusage.Bucket `json:"buckets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Buckets) != 1 || out.Buckets[0].ClientID != "client-a" {
		t.Fatalf("buckets = %+v, want exactly client-a", out.Buckets)
	}
}

// TestHandleAdminUsage_EmptyResultIsEmptyArrayNotNull guards the JSON
// contract: an admin dashboard parsing `buckets` must always see an array,
// never a literal `null`, even when the store has nothing to return.
func TestHandleAdminUsage_EmptyResultIsEmptyArrayNotNull(t *testing.T) {
	store := New()
	ctx, rec := newAdminCtx(t, "/admin/tokens/usage?client_id=nobody")
	tokenusage.HandleAdminUsage(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	arr, ok := out["buckets"].([]any)
	if !ok || len(arr) != 0 {
		t.Fatalf("buckets = %#v, want a literal empty array", out["buckets"])
	}
}

// TestHandleAdminUsage_BadSinceIsBadRequest proves a malformed `since`
// query parameter yields 400 invalid_request rather than a 500 or a
// silently-ignored filter.
func TestHandleAdminUsage_BadSinceIsBadRequest(t *testing.T) {
	store := New()
	ctx, rec := newAdminCtx(t, "/admin/tokens/usage?since=not-a-time")
	tokenusage.HandleAdminUsage(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["error"] != core.ErrInvalidRequest {
		t.Errorf("error = %v, want %s", out["error"], core.ErrInvalidRequest)
	}
}

// TestHandleAdminUsage_BadUntilIsBadRequest mirrors the since case for the
// until parameter.
func TestHandleAdminUsage_BadUntilIsBadRequest(t *testing.T) {
	store := New()
	ctx, rec := newAdminCtx(t, "/admin/tokens/usage?until=not-a-time")
	tokenusage.HandleAdminUsage(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestHandleAdminUsage_SinceUntilWindowFilters proves a well-formed
// RFC 3339 [since, until) window narrows results the same way the Store's
// own Query contract does — the handler is a thin bind, not a
// re-implementation.
func TestHandleAdminUsage_SinceUntilWindowFilters(t *testing.T) {
	store := New()
	seedStore(t, store, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, 0)
	seedStore(t, store, "client-a", tokenusage.KindAccess, tokenusage.EndpointToken, 5)

	ctx, rec := newAdminCtx(t, "/admin/tokens/usage?since=2026-07-01T00:00:00Z&until=2026-07-01T00:01:00Z")
	tokenusage.HandleAdminUsage(store, spi.NopLogger{}, ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out struct {
		Buckets []tokenusage.Bucket `json:"buckets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Buckets) != 1 {
		t.Fatalf("buckets = %+v, want exactly 1 within the window", out.Buckets)
	}
}
