package netpolicy_test

// HTTP-handler tests for the netpolicy admin/classify endpoints. External
// package (netpolicy_test) because the handlers pull in core + audit and the
// real netpolicy/memory backend, which would cycle from an in-package test.
// A small testDeps satisfies netpolicy.HandlerDeps backed entirely by the real
// memory Store + a real audit.Recorder over a MemorySink — no mocks.
//
// Param-bearing routes (:name on Get/Delete) are driven through a real
// core.StdRouter so the param is extracted exactly as in production; the
// param-free routes use core.NewContext directly.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/platform/netpolicy/memory"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type testDeps struct {
	store netpolicy.Store
	cls   *netpolicy.Classifier
	rec   *audit.Recorder
}

func (d *testDeps) NetStore() netpolicy.Store            { return d.store }
func (d *testDeps) NetClassifier() *netpolicy.Classifier { return d.cls }
func (d *testDeps) Auditor() *audit.Recorder             { return d.rec }
func (d *testDeps) SrvLogger() spi.Logger                { return spi.NopLogger{} }

var _ netpolicy.HandlerDeps = (*testDeps)(nil)

// nilStoreDeps returns deps with a nil Store/Classifier to exercise the
// not-configured guards. The interface methods return typed-nil so the handler's
// `== nil` checks fire.
type nilStoreDeps struct{}

func (nilStoreDeps) NetStore() netpolicy.Store            { return nil }
func (nilStoreDeps) NetClassifier() *netpolicy.Classifier { return nil }
func (nilStoreDeps) Auditor() *audit.Recorder             { return nil }
func (nilStoreDeps) SrvLogger() spi.Logger                { return spi.NopLogger{} }

func newTestDeps() (*testDeps, *audit.MemorySink) {
	sink := audit.NewMemorySink(64)
	return &testDeps{
		store: memory.New(),
		cls:   netpolicy.NewClassifier(),
		rec:   audit.New(sink),
	}, sink
}

// decode unmarshals a recorder body into a generic map.
func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return m
}

// router builds a StdRouter wiring the param-bearing handlers against d so we
// get production param extraction for :name.
func router(d netpolicy.HandlerDeps) *core.StdRouter {
	r := core.NewStdRouter()
	r.GET("/policies/:name", func(ctx core.HandlerContext) { netpolicy.HandleGet(d, ctx) })
	r.DELETE("/policies/:name", func(ctx core.HandlerContext) { netpolicy.HandleDelete(d, ctx) })
	return r
}

func TestHandleListEmptyAndPopulated(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()

	// Empty store → empty list, 200.
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/policies", nil))
	netpolicy.HandleList(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleList empty code=%d", rec.Code)
	}

	if _, err := d.store.Apply(ctx.Request().Context(), &netpolicy.Policy{Name: "p1", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec = httptest.NewRecorder()
	ctx = core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/policies", nil))
	netpolicy.HandleList(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleList code=%d", rec.Code)
	}
	body := decode(t, rec)
	if _, ok := body[core.KeyNetPolicies]; !ok {
		t.Fatalf("HandleList body missing %q: %v", core.KeyNetPolicies, body)
	}
}

func TestHandleListNilStore(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/policies", nil))
	netpolicy.HandleList(nilStoreDeps{}, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil-store HandleList code=%d, want 500", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrNetPolicyNotConfigured {
		t.Fatalf("nil-store HandleList wrong error: %v", rec.Body.String())
	}
}

func TestHandleGetFound(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	if _, err := d.store.Apply(context.Background(),
		&netpolicy.Policy{Name: "found", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policies/found", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleGet code=%d", rec.Code)
	}
	body := decode(t, rec)
	pol, ok := body[core.KeyNetPolicy].(map[string]any)
	if !ok || pol["name"] != "found" {
		t.Fatalf("HandleGet body = %v", body)
	}
}

func TestHandleGetNotFound(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policies/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("HandleGet missing code=%d, want 404", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrNetPolicyNotFound {
		t.Fatalf("HandleGet missing wrong error: %v", rec.Body.String())
	}
}

func TestHandleGetEmptyName(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	// No router → Param("name") is "" → bad request branch.
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/policies/", nil))
	netpolicy.HandleGet(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleGet empty name code=%d, want 400", rec.Code)
	}
}

func TestHandleGetNilStore(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/policies/x", nil))
	netpolicy.HandleGet(nilStoreDeps{}, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil-store HandleGet code=%d, want 500", rec.Code)
	}
}

func TestHandleApplyCreatesAndAudits(t *testing.T) {
	t.Parallel()
	d, sink := newTestDeps()

	payload := netpolicy.Payload{Name: "new", CIDRs: []string{"10.0.0.0/8"}, Priority: 5, Metadata: map[string]string{"k": "v"}}
	buf, _ := json.Marshal(payload)
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(buf)))
	netpolicy.HandleApply(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleApply code=%d body=%s", rec.Code, rec.Body.String())
	}
	// Persisted in the store with a stamped version.
	got, err := d.store.Get(ctx.Request().Context(), "new")
	if err != nil {
		t.Fatalf("policy not stored: %v", err)
	}
	if got.Version == 0 {
		t.Fatalf("Version not stamped: %+v", got)
	}
	// A mutation audit event was recorded synchronously.
	if sink.Len() != 1 {
		t.Fatalf("audit events = %d, want 1", sink.Len())
	}
}

func TestHandleApplyBadJSON(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader([]byte("{not json"))))
	netpolicy.HandleApply(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleApply bad json code=%d, want 400", rec.Code)
	}
}

func TestHandleApplyMissingName(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	buf, _ := json.Marshal(netpolicy.Payload{CIDRs: []string{"10.0.0.0/8"}})
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(buf)))
	netpolicy.HandleApply(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleApply missing name code=%d, want 400", rec.Code)
	}
}

func TestHandleApplyNilStore(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader([]byte("{}"))))
	netpolicy.HandleApply(nilStoreDeps{}, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil-store HandleApply code=%d, want 500", rec.Code)
	}
}

func TestHandleApplyNilAuditorNoPanic(t *testing.T) {
	t.Parallel()
	// Auditor() nil → recordMutation early-returns; the apply still succeeds.
	d := &testDeps{store: memory.New(), cls: netpolicy.NewClassifier(), rec: nil}
	buf, _ := json.Marshal(netpolicy.Payload{Name: "noaudit", CIDRs: []string{"10.0.0.0/8"}})
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(buf)))
	netpolicy.HandleApply(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleApply nil auditor code=%d, want 200", rec.Code)
	}
}

func TestHandleDeleteAudits(t *testing.T) {
	t.Parallel()
	d, sink := newTestDeps()
	if _, err := d.store.Apply(context.Background(),
		&netpolicy.Policy{Name: "doomed"}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/policies/doomed", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleDelete code=%d", rec.Code)
	}
	if decode(t, rec)[core.KeyStatus] != core.StatusOK {
		t.Fatalf("HandleDelete status body = %v", rec.Body.String())
	}
	if _, err := d.store.Get(context.Background(), "doomed"); err == nil {
		t.Fatal("policy still present after delete")
	}
	if sink.Len() != 1 {
		t.Fatalf("delete audit events = %d, want 1", sink.Len())
	}
}

func TestHandleDeleteEmptyName(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodDelete, "/policies/", nil))
	netpolicy.HandleDelete(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("HandleDelete empty name code=%d, want 400", rec.Code)
	}
}

func TestHandleDeleteNilStore(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodDelete, "/policies/x", nil))
	netpolicy.HandleDelete(nilStoreDeps{}, ctx)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("nil-store HandleDelete code=%d, want 500", rec.Code)
	}
}

func TestHandleClassifyMatchAndMiss(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	if err := d.cls.Reload(context.Background(), seedStore(t)); err != nil {
		t.Fatalf("reload classifier: %v", err)
	}

	// Match by remote_addr.
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/classify?remote_addr=10.0.0.1", nil))
	netpolicy.HandleClassify(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleClassify match code=%d", rec.Code)
	}
	if decode(t, rec)[core.KeyNetClass] != "intranet" {
		t.Fatalf("HandleClassify match class = %v", rec.Body.String())
	}

	// Miss → empty class, still 200.
	rec = httptest.NewRecorder()
	ctx = core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/classify?remote_addr=8.8.8.8", nil))
	netpolicy.HandleClassify(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleClassify miss code=%d", rec.Code)
	}
	if decode(t, rec)[core.KeyNetClass] != "" {
		t.Fatalf("HandleClassify miss class = %v", rec.Body.String())
	}
}

func TestHandleClassifyNilClassifier(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/classify", nil))
	netpolicy.HandleClassify(nilStoreDeps{}, ctx)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("nil-classifier HandleClassify code=%d, want 501", rec.Code)
	}
}

func TestHandleResolveMeMatchAndMiss(t *testing.T) {
	t.Parallel()
	d, _ := newTestDeps()
	if err := d.cls.Reload(context.Background(), seedStore(t)); err != nil {
		t.Fatalf("reload classifier: %v", err)
	}

	// RemoteAddr matches the seeded intranet CIDR.
	req := httptest.NewRequest(http.MethodGet, "/resolve-me", nil)
	req.RemoteAddr = "10.0.0.7:5555"
	rec := httptest.NewRecorder()
	netpolicy.HandleResolveMe(d, core.NewContext(rec, req))
	if rec.Code != http.StatusOK {
		t.Fatalf("HandleResolveMe code=%d", rec.Code)
	}
	if decode(t, rec)[core.KeyNetClass] != "intranet" {
		t.Fatalf("HandleResolveMe class = %v", rec.Body.String())
	}

	// A request from outside any class → empty class.
	req = httptest.NewRequest(http.MethodGet, "/resolve-me", nil)
	req.RemoteAddr = "8.8.8.8:1234"
	req.Host = "unknown.example.com"
	rec = httptest.NewRecorder()
	netpolicy.HandleResolveMe(d, core.NewContext(rec, req))
	if decode(t, rec)[core.KeyNetClass] != "" {
		t.Fatalf("HandleResolveMe miss class = %v", rec.Body.String())
	}
}

func TestHandleResolveMeNilClassifier(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/resolve-me", nil))
	netpolicy.HandleResolveMe(nilStoreDeps{}, ctx)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("nil-classifier HandleResolveMe code=%d, want 501", rec.Code)
	}
}

// errDeps wires an error-injecting Store so the handlers' store-error branches
// (500 ErrInternal) are exercised. The classifier + auditor are real.
func errDeps(es *errStore) *testDeps {
	return &testDeps{store: es, cls: netpolicy.NewClassifier(), rec: nil}
}

func TestHandleListStoreError(t *testing.T) {
	t.Parallel()
	d := errDeps(&errStore{inner: memory.New(), failList: true})
	rec := httptest.NewRecorder()
	netpolicy.HandleList(d, core.NewContext(rec, httptest.NewRequest(http.MethodGet, "/policies", nil)))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleList store error code=%d, want 500", rec.Code)
	}
	if decode(t, rec)[core.KeyError] != core.ErrInternal {
		t.Fatalf("HandleList store error body = %v", rec.Body.String())
	}
}

func TestHandleGetStoreError(t *testing.T) {
	t.Parallel()
	d := errDeps(&errStore{inner: memory.New(), failGet: true})
	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policies/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleGet store error code=%d, want 500", rec.Code)
	}
}

func TestHandleApplyStoreError(t *testing.T) {
	t.Parallel()
	d := errDeps(&errStore{inner: memory.New(), failApply: true})
	buf, _ := json.Marshal(netpolicy.Payload{Name: "x", CIDRs: []string{"10.0.0.0/8"}})
	rec := httptest.NewRecorder()
	netpolicy.HandleApply(d, core.NewContext(rec, httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(buf))))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleApply store error code=%d, want 500", rec.Code)
	}
}

func TestHandleDeleteStoreError(t *testing.T) {
	t.Parallel()
	d := errDeps(&errStore{inner: memory.New(), failDelete: true})
	rec := httptest.NewRecorder()
	router(d).ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/policies/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("HandleDelete store error code=%d, want 500", rec.Code)
	}
}

// seedStore returns a memory Store pre-populated with an "intranet" 10.0.0.0/8
// policy, used to seed a Classifier under test.
func seedStore(t *testing.T) *memory.Store {
	t.Helper()
	s := memory.New()
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Apply(context.Background(),
		&netpolicy.Policy{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("seedStore apply: %v", err)
	}
	return s
}
