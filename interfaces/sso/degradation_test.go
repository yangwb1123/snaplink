package sso

// Integration tests for the DR degraded-service gate wired through the full
// Handler() middleware chain. Package sso (not sso_test) so the tests can reach
// the unexported degradation field + reuse busSeriesValue / busCountEvents from
// the sibling self-heal tests.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/core"
)

func drDo(h http.Handler, method, path string, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// drRejectedByGate reports whether the response is specifically the DR gate's
// 503 (status + service_degraded body), so a pass-case assertion can't be
// fooled by an unrelated downstream 503.
func drRejectedByGate(rec *httptest.ResponseRecorder) bool {
	if rec.Code != http.StatusServiceUnavailable {
		return false
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Error == core.ErrServiceDegraded
}

func TestServer_DegradationDefaultOff(t *testing.T) {
	s := NewServer()
	if s.degradation != nil {
		t.Fatal("degradation must be nil without WithDegradationManager")
	}
	// A default build must not gate any request.
	if drRejectedByGate(drDo(s.Handler(), http.MethodGet, PathHealth, "")) {
		t.Fatal("default build must not install the DR gate")
	}
}

func TestServer_DegradationModesEnforced(t *testing.T) {
	m := NewDegradationManager(DegradationModeNormal)
	mm := metrics.New()
	s := NewServer(WithDegradationManager(m), WithMetrics(mm))
	h := s.Handler()

	if v := busSeriesValue(t, mm, "sso_degradation_mode", map[string]string{"mode": "normal"}); v != 1 {
		t.Fatalf("initial mode gauge normal = %v, want 1", v)
	}

	// maintenance: all non-probe requests 503 + Retry-After; probes + the DR
	// toggle stay reachable.
	mustSet(t, m, DegradationModeMaintenance, "drill")
	rec := drDo(h, http.MethodGet, PathHealth, "")
	if !drRejectedByGate(rec) {
		t.Fatalf("maintenance must refuse /health, got %d", rec.Code)
	}
	if rec.Header().Get(core.HeaderRetryAfter) == "" {
		t.Fatal("maintenance 503 missing Retry-After")
	}
	for _, probe := range []string{PathLivez, PathReadyz} {
		if code := drDo(h, http.MethodGet, probe, "").Code; code != http.StatusOK {
			t.Fatalf("probe %s must pass in maintenance, got %d", probe, code)
		}
	}
	if drRejectedByGate(drDo(h, http.MethodGet, PathAPIPrefix+PathDRMode, "")) {
		t.Fatal("DR toggle must stay reachable in maintenance (recovery lever)")
	}
	if v := busSeriesValue(t, mm, "sso_degradation_mode", map[string]string{"mode": "maintenance"}); v != 1 {
		t.Fatalf("maintenance gauge = %v, want 1", v)
	}
	if v := busSeriesValue(t, mm, "sso_degradation_mode", map[string]string{"mode": "normal"}); v != 0 {
		t.Fatalf("normal gauge after transition = %v, want 0", v)
	}
	if v := busSeriesValue(t, mm, "sso_degraded_rejections_total", map[string]string{"mode": "maintenance", "method": "GET"}); v < 1 {
		t.Fatalf("rejection counter = %v, want >= 1", v)
	}

	// read_only: reads pass, mutating admin write refused, token plane stays.
	mustSet(t, m, DegradationModeReadOnly, "")
	if drRejectedByGate(drDo(h, http.MethodGet, PathHealth, "")) {
		t.Fatal("read_only must allow reads")
	}
	if !drRejectedByGate(drDo(h, http.MethodPost, PathAPIPrefix+"/admin/clients", "")) {
		t.Fatal("read_only must refuse a mutating admin write")
	}
	if drRejectedByGate(drDo(h, http.MethodPost, PathToken, "")) {
		t.Fatal("read_only must keep /token reachable")
	}

	// auth_only: login + token pass; admin/self-service refused.
	mustSet(t, m, DegradationModeAuthOnly, "")
	if drRejectedByGate(drDo(h, http.MethodPost, PathLogin, "")) {
		t.Fatal("auth_only must keep /auth/login reachable")
	}
	if !drRejectedByGate(drDo(h, http.MethodGet, PathAPIPrefix+"/admin/clients", "")) {
		t.Fatal("auth_only must refuse admin")
	}
	if !drRejectedByGate(drDo(h, http.MethodGet, PathMe, "")) {
		t.Fatal("auth_only must refuse self-service /me")
	}
}

func TestServer_DRModeAdminEndpoint(t *testing.T) {
	m := NewDegradationManager(DegradationModeNormal)
	s := NewServer(WithDegradationManager(m))
	h := s.Handler()
	full := PathAPIPrefix + PathDRMode

	if code := drDo(h, http.MethodPost, full, `{"mode":"read_only","reason":"t"}`).Code; code != http.StatusOK {
		t.Fatalf("set mode = %d, want 200", code)
	}
	if m.Mode() != DegradationModeReadOnly {
		t.Fatalf("mode not applied via endpoint, got %q", m.Mode())
	}
	var got struct {
		Mode string `json:"mode"`
	}
	_ = json.Unmarshal(drDo(h, http.MethodGet, full, "").Body.Bytes(), &got)
	if got.Mode != "read_only" {
		t.Fatalf("GET mode body = %q, want read_only", got.Mode)
	}
	if code := drDo(h, http.MethodPost, full, `{"mode":"nope"}`).Code; code != http.StatusBadRequest {
		t.Fatalf("invalid mode = %d, want 400", code)
	}
}

func TestServer_DRModeChangeAudited(t *testing.T) {
	m := NewDegradationManager(DegradationModeNormal)
	sink := audit.NewMemorySink(0)
	// Retaining the server is unnecessary: WithDegradationManager binds the
	// server's change hook onto m, so m keeps it alive.
	_ = NewServer(WithDegradationManager(m), WithAuditRecorder(audit.New(sink)))

	mustSet(t, m, DegradationModeMaintenance, "planned")
	if n := busCountEvents(t, sink, audit.EventDegradationModeChanged); n != 1 {
		t.Fatalf("degradation audit events = %d, want 1", n)
	}
	// A no-op transition emits no further audit noise.
	mustSet(t, m, DegradationModeMaintenance, "again")
	if n := busCountEvents(t, sink, audit.EventDegradationModeChanged); n != 1 {
		t.Fatalf("no-op transition should not audit; events = %d, want 1", n)
	}
}

func mustSet(t *testing.T, m *DegradationManager, mode DegradationMode, reason string) {
	t.Helper()
	if _, err := m.SetMode(context.Background(), mode, reason); err != nil {
		t.Fatalf("SetMode(%q): %v", mode, err)
	}
}
