package audit_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// noopLogger satisfies spi.Logger for the HTTP handler tests without
// printing anything. Real logger, no mocks framework.
type noopLogger struct{}

func (noopLogger) Info(string, ...any)  {}
func (noopLogger) Error(string, ...any) {}
func (noopLogger) Debug(string, ...any) {}

// handlerDeps is the minimal HandlerDeps the audit HTTP handlers need.
// *sso.Server satisfies the same interface in production via accessors.
type handlerDeps struct{ rec *audit.Recorder }

func (d handlerDeps) Auditor() *audit.Recorder { return d.rec }
func (d handlerDeps) SrvLogger() spi.Logger    { return noopLogger{} }

// writeOnlySink rejects all reads with ErrSinkWriteOnly so the handlers'
// read-capability fallbacks are exercised. Record is a no-op success and
// it deliberately does NOT implement FacetQuerier.
type writeOnlySink struct{}

func (writeOnlySink) Record(context.Context, *audit.Event) error { return nil }
func (writeOnlySink) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}
func (writeOnlySink) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// httpCtx builds a HandlerContext for a GET with the supplied raw query
// string and optional :id param.
func httpCtx(t *testing.T, rawQuery, id string) (core.HandlerContext, *httptest.ResponseRecorder) {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/audit/events?"+rawQuery, nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)
	return paramCtx{Context: ctx, id: id}, w
}

// paramCtx layers a :id route param onto a core.Context (StdRouter would
// inject it in production; here we supply it directly).
type paramCtx struct {
	*core.Context
	id string
}

func (p paramCtx) Param(name string) string {
	if name == "id" {
		return p.id
	}
	return p.Context.Param(name)
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", w.Body.String(), err)
	}
	return m
}

func seededRecorder(t *testing.T) *audit.Recorder {
	t.Helper()
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ClientID: "c1"})
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, ClientID: "c2"})
	return rec
}

func TestHandleEvents_ReturnsEventsAndCount(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "", "")
	audit.HandleEvents(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	m := decodeBody(t, w)
	if n, _ := m["count"].(float64); int(n) != 2 {
		t.Fatalf("count = %v, want 2", m["count"])
	}
}

func TestHandleEvents_FilterByClientID(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "client_id=c1", "")
	audit.HandleEvents(d, ctx)
	m := decodeBody(t, w)
	if n, _ := m["count"].(float64); int(n) != 1 {
		t.Fatalf("filtered count = %v, want 1", m["count"])
	}
}

func TestHandleEvents_NilRecorder500(t *testing.T) {
	d := handlerDeps{rec: nil}
	ctx, w := httpCtx(t, "", "")
	audit.HandleEvents(d, ctx)
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	if decodeBody(t, w)[core.KeyError] != audit.ErrNotEnabled {
		t.Fatalf("error = %v, want %q", decodeBody(t, w)[core.KeyError], audit.ErrNotEnabled)
	}
}

func TestHandleEvents_BadQueryParam400(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "limit=notanumber", "")
	audit.HandleEvents(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleEvents_BadSinceTimestamp400(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "since=garbage", "")
	audit.HandleEvents(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleEvents_QueryStoreError500(t *testing.T) {
	rec := audit.New(writeOnlySink{}) // Query returns ErrSinkWriteOnly (non-nil)
	d := handlerDeps{rec: rec}
	ctx, w := httpCtx(t, "", "")
	audit.HandleEvents(d, ctx)
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500 (store error)", w.Code)
	}
}

func TestHandleEvents_AcceptsRFC3339AndUnixTimestamps(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	for _, q := range []string{"since=2020-01-01T00:00:00Z", "since=1577836800", "until=2099-01-01T00:00:00Z", "offset=0&limit=5"} {
		ctx, w := httpCtx(t, q, "")
		audit.HandleEvents(d, ctx)
		if w.Code != 200 {
			t.Fatalf("query %q status = %d, body=%s", q, w.Code, w.Body.String())
		}
	}
}

func TestHandleEventByID_Found(t *testing.T) {
	sink := audit.NewMemorySink(4)
	rec := audit.New(sink)
	rec.Record(context.Background(), &audit.Event{ID: "evt-42", Type: audit.EventLogin})
	d := handlerDeps{rec: rec}
	ctx, w := httpCtx(t, "", "evt-42")
	audit.HandleEventByID(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if decodeBody(t, w)["id"] != "evt-42" {
		t.Fatalf("id = %v", decodeBody(t, w)["id"])
	}
}

func TestHandleEventByID_MissingIDParam400(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "", "")
	audit.HandleEventByID(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleEventByID_NotFound404(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "", "does-not-exist")
	audit.HandleEventByID(d, ctx)
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	if decodeBody(t, w)[core.KeyError] != audit.ErrEventNotFoundCode {
		t.Fatalf("error = %v", decodeBody(t, w)[core.KeyError])
	}
}

func TestHandleEventByID_NilRecorder500(t *testing.T) {
	d := handlerDeps{rec: nil}
	ctx, w := httpCtx(t, "", "x")
	audit.HandleEventByID(d, ctx)
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestHandleEventByID_StoreError500(t *testing.T) {
	rec := audit.New(writeOnlySink{}) // Get returns ErrSinkWriteOnly (not ErrEventNotFound)
	d := handlerDeps{rec: rec}
	ctx, w := httpCtx(t, "", "any")
	audit.HandleEventByID(d, ctx)
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestHandleFacets_MemorySinkAggregates(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "", "")
	audit.HandleFacets(d, ctx)
	if w.Code != 200 {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if _, ok := decodeBody(t, w)[audit.KeyFacets]; !ok {
		t.Fatalf("missing facets key: %s", w.Body.String())
	}
}

func TestHandleFacets_NilRecorder500(t *testing.T) {
	d := handlerDeps{rec: nil}
	ctx, w := httpCtx(t, "", "")
	audit.HandleFacets(d, ctx)
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestHandleFacets_WriteOnlySink501(t *testing.T) {
	// writeOnlySink does not implement FacetQuerier -> 501.
	rec := audit.New(writeOnlySink{})
	d := handlerDeps{rec: rec}
	ctx, w := httpCtx(t, "", "")
	audit.HandleFacets(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
	if decodeBody(t, w)[core.KeyError] != audit.ErrNotEnabled {
		t.Fatalf("error = %v", decodeBody(t, w)[core.KeyError])
	}
}

func TestHandleFacets_BadQueryParam400(t *testing.T) {
	d := handlerDeps{rec: seededRecorder(t)}
	ctx, w := httpCtx(t, "limit=NaN", "")
	audit.HandleFacets(d, ctx)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// A FacetQuerier that reports the capability missing at call time
// (ErrFacetsUnsupported) maps to 501 — the AsyncSink/MultiSink-over-
// write-only-leaf path.
type facetUnsupportedSink struct{ writeOnlySink }

func (facetUnsupportedSink) Facets(context.Context, audit.Query) (*audit.Facets, error) {
	return nil, audit.ErrFacetsUnsupported
}

func TestHandleFacets_CallTimeUnsupported501(t *testing.T) {
	rec := audit.New(facetUnsupportedSink{})
	d := handlerDeps{rec: rec}
	ctx, w := httpCtx(t, "", "")
	audit.HandleFacets(d, ctx)
	if w.Code != 501 {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

// A FacetQuerier returning a generic error maps to 500.
type facetErrorSink struct{ writeOnlySink }

func (facetErrorSink) Facets(context.Context, audit.Query) (*audit.Facets, error) {
	return nil, context.DeadlineExceeded
}

func TestHandleFacets_GenericError500(t *testing.T) {
	rec := audit.New(facetErrorSink{})
	d := handlerDeps{rec: rec}
	ctx, w := httpCtx(t, "", "")
	audit.HandleFacets(d, ctx)
	if w.Code != 500 {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}
