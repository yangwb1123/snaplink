package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
)

// TestAuditFacets_ReturnsCounts exercises GET /api/v1/audit/facets against
// the seeded MemorySink: the three events (login + login_failure + logout;
// 2 success / 1 failure; all client web) roll up into the bounded
// dimensions the filter UI renders.
func TestAuditFacets_ReturnsCounts(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/facets")
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	f, ok := body["facets"].(map[string]any)
	if !ok {
		t.Fatalf("missing facets object: %v", body)
	}
	if total, _ := f["total"].(float64); int(total) != 3 {
		t.Errorf("total = %v, want 3", f["total"])
	}
	outcomes, _ := f["outcomes"].(map[string]any)
	if int(outcomes["success"].(float64)) != 2 || int(outcomes["failure"].(float64)) != 1 {
		t.Errorf("outcomes = %v, want success=2 failure=1", outcomes)
	}
	types, _ := f["types"].(map[string]any)
	if int(types["login"].(float64)) != 1 || int(types["login_failure"].(float64)) != 1 || int(types["logout"].(float64)) != 1 {
		t.Errorf("types = %v", types)
	}
	clients, _ := f["clients"].(map[string]any)
	if int(clients["web"].(float64)) != 3 {
		t.Errorf("clients = %v, want web=3", clients)
	}
}

// TestAuditFacets_HonorsFilter proves the facet window respects the same
// query filters as the events endpoint (here: only the failure event).
func TestAuditFacets_HonorsFilter(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/facets?outcome=failure")
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	f := body["facets"].(map[string]any)
	if total, _ := f["total"].(float64); int(total) != 1 {
		t.Errorf("filtered total = %v, want 1", f["total"])
	}
}

// TestAuditFacets_BadParam mirrors the events endpoint's 400 on a
// malformed time filter (parseQuery is shared).
func TestAuditFacets_BadParam(t *testing.T) {
	h := newAuditHarness(t, true)
	code, body := auditGET(t, h, "/api/v1/audit/facets?since=not-a-time")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if e, _ := body["error"].(string); e != "invalid_request" {
		t.Errorf("error = %v", e)
	}
}

// facetlessSink is a read-capable Sink that deliberately does NOT
// implement audit.FacetQuerier, so the handler must fall back to 501.
type facetlessSink struct{ inner *audit.MemorySink }

func (s facetlessSink) Record(ctx context.Context, e *audit.Event) error {
	return s.inner.Record(ctx, e)
}
func (s facetlessSink) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error) {
	return s.inner.Query(ctx, q)
}
func (s facetlessSink) Get(ctx context.Context, id string) (*audit.Event, error) {
	return s.inner.Get(ctx, id)
}

// TestAuditFacets_NotImplementedWhenSinkLacksSupport proves a Sink without
// FacetQuerier yields 501 audit_not_enabled (the optional-capability
// fallback) while the events endpoint still works.
func TestAuditFacets_NotImplementedWhenSinkLacksSupport(t *testing.T) {
	rec := audit.New(facetlessSink{inner: audit.NewMemorySink(10)})
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess})

	srv := sso.NewServer(sso.WithAuditRecorder(rec), sso.WithAuditAPI())
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Get(httpSrv.URL + "/api/v1/audit/facets")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if e, _ := out["error"].(string); e != "audit_not_enabled" {
		t.Errorf("error = %v, want audit_not_enabled", e)
	}

	// The events endpoint still works against the same sink.
	ev, err := http.Get(httpSrv.URL + "/api/v1/audit/events")
	if err != nil {
		t.Fatalf("get events: %v", err)
	}
	defer func() { _ = ev.Body.Close() }()
	if ev.StatusCode != http.StatusOK {
		t.Errorf("events status = %d, want 200", ev.StatusCode)
	}
}

// newAuditFacetsAdminHarness mounts the audit API behind the admin
// middleware so the gating tests exercise the real /api/v1/audit/* prefix
// rule (IsProtectedPath) the same way production wires it.
func newAuditFacetsAdminHarness(t *testing.T, validClaims *sso.TokenClaims) *httptest.Server {
	t.Helper()
	rec := audit.New(audit.NewMemorySink(10))
	rec.Record(context.Background(), &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ClientID: "web", Provider: "password"})

	srv := sso.NewServer(sso.WithAuditRecorder(rec), sso.WithAuditAPI())
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: validClaims}, adminProvider(t))
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestAuditFacets_AdminGated_NoToken401(t *testing.T) {
	srv := newAuditFacetsAdminHarness(t, &sso.TokenClaims{Subject: "user-alice"})
	resp := httpDo(t, "GET", srv.URL+"/api/v1/audit/facets", "")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate challenge on 401")
	}
}

func TestAuditFacets_AdminGated_NoScope403(t *testing.T) {
	rec := audit.New(audit.NewMemorySink(10))
	srv := sso.NewServer(sso.WithAuditRecorder(rec), sso.WithAuditAPI())
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-bob"}}, nonAdminProvider(t))
	httpSrv := httptest.NewServer(mw.HTTPMiddleware(srv.Handler()))
	t.Cleanup(httpSrv.Close)

	resp := httpDo(t, "GET", httpSrv.URL+"/api/v1/audit/facets", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAuditFacets_AdminGated_WithScope200(t *testing.T) {
	srv := newAuditFacetsAdminHarness(t, &sso.TokenClaims{Subject: "user-alice"})
	resp := httpDo(t, "GET", srv.URL+"/api/v1/audit/facets", "good")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if _, ok := out["facets"]; !ok {
		t.Errorf("missing facets in body: %v", out)
	}
}
