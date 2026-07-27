package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/platform/lifecycle/degradation"
)

func drTestPolicy() degradation.Policy {
	return degradation.Policy{
		ProbePaths:     []string{"/livez", "/readyz", "/metrics"},
		ReadOnlyExempt: []string{"/token", "/token/introspect"},
		AuthOnlyAllow:  []string{"/auth/", "/token", "/.well-known/"},
		LocalOnlyBlock: []string{"/ssf/receive"},
	}
}

func newDRHandler(m *degradation.Manager) http.Handler {
	var rejected []string
	cfg := DegradationConfig{
		Controller: m,
		Policy:     drTestPolicy(),
		OnReject: func(mode degradation.Mode, r *http.Request) {
			rejected = append(rejected, string(mode)+" "+r.Method+" "+r.URL.Path)
		},
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return Degradation(cfg)(next)
}

func TestDegradation_PassThroughInNormal(t *testing.T) {
	h := newDRHandler(degradation.NewManager(degradation.ModeNormal))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("normal mode should pass, got %d", rec.Code)
	}
}

func TestDegradation_MaintenanceRefusesWithRetryAfter(t *testing.T) {
	h := newDRHandler(degradation.NewManager(degradation.ModeMaintenance))

	// Non-probe request is refused with 503 + Retry-After.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/userinfo", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("maintenance should refuse, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("missing Retry-After on degraded 503")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	// Probe still passes even in maintenance.
	probe := httptest.NewRecorder()
	h.ServeHTTP(probe, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if probe.Code != http.StatusOK {
		t.Fatalf("probe must pass in maintenance, got %d", probe.Code)
	}
}

func TestDegradation_ReadOnlyBlocksMutations(t *testing.T) {
	h := newDRHandler(degradation.NewManager(degradation.ModeReadOnly))
	cases := []struct {
		method, path string
		wantCode     int
	}{
		{http.MethodGet, "/userinfo", http.StatusOK},
		{http.MethodPost, "/token", http.StatusOK},
		{http.MethodPost, "/api/v1/admin/clients", http.StatusServiceUnavailable},
		{http.MethodDelete, "/me/sessions/x", http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.wantCode {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.wantCode)
		}
	}
}

func TestDegradation_NilControllerPassThrough(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := Degradation(DegradationConfig{Policy: drTestPolicy()})(next)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("nil controller must pass through, got %d", rec.Code)
	}
}
