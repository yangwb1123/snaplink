package sso

// Integration tests for ADR-0008's opt-in HTTP API versioning mechanism —
// Accept-Version negotiation, Sunset/Deprecation response headers, and the
// v2alpha proof-of-mechanism route — wired through the full Handler()
// middleware chain. Package sso (not sso_test) so the tests can reach the
// unexported fields these options set, mirroring degradation_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/middleware"
)

func avDo(h http.Handler, method, path, acceptVersion string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if acceptVersion != "" {
		r.Header.Set("Accept-Version", acceptVersion)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestServer_APIVersioning_DefaultByteIdentical(t *testing.T) {
	s := NewServer()
	h := s.Handler()

	// No WithAPIVersioning ⇒ Accept-Version is never even inspected: an
	// unrecognized value must NOT be rejected.
	if code := avDo(h, http.MethodGet, PathHealth, "v99-does-not-exist").Code; code != http.StatusOK {
		t.Fatalf("unconfigured server must ignore Accept-Version entirely, got %d", code)
	}
	// No WithAPIDeprecation/WithRouteDeprecation ⇒ no Deprecation/Sunset headers.
	rec := avDo(h, http.MethodGet, PathHealth, "")
	if v := rec.Header().Get("Deprecation"); v != "" {
		t.Fatalf("unconfigured server must not add Deprecation header, got %q", v)
	}
	if v := rec.Header().Get("Sunset"); v != "" {
		t.Fatalf("unconfigured server must not add Sunset header, got %q", v)
	}
	// No WithAPIVersionPreview ⇒ the v2alpha route is not mounted (router-native 404).
	if code := avDo(h, http.MethodGet, "/api/v2alpha/version", "").Code; code != http.StatusNotFound {
		t.Fatalf("v2alpha route must be unmounted by default, got %d", code)
	}
}

func TestServer_AcceptVersion_Negotiation(t *testing.T) {
	s := NewServer(WithAPIVersioning("v1", "v2alpha"))
	h := s.Handler()

	if code := avDo(h, http.MethodGet, PathHealth, "").Code; code != http.StatusOK {
		t.Fatalf("no Accept-Version header must pass through, got %d", code)
	}
	if code := avDo(h, http.MethodGet, PathHealth, "v1").Code; code != http.StatusOK {
		t.Fatalf("supported version must pass through, got %d", code)
	}
	rec := avDo(h, http.MethodGet, PathHealth, "v99")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported version = %d, want 400", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.Error != "unsupported_version" {
		t.Fatalf("error code = %q, want unsupported_version", body.Error)
	}
}

func TestServer_APIDeprecation_WholeAPI(t *testing.T) {
	sunset := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	s := NewServer(WithAPIDeprecation(middleware.DeprecationPolicy{Sunset: sunset}))
	h := s.Handler()

	rec := avDo(h, http.MethodGet, PathHealth, "")
	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Fatalf("Deprecation header = %q, want true", got)
	}
	if got := rec.Header().Get("Sunset"); got != sunset.Format(http.TimeFormat) {
		t.Fatalf("Sunset header = %q", got)
	}
}

func TestServer_RouteDeprecation_ScopedToPath(t *testing.T) {
	s := NewServer(WithRouteDeprecation(PathHealth, middleware.DeprecationPolicy{Link: "https://example.com/migrate"}))
	h := s.Handler()

	onPath := avDo(h, http.MethodGet, PathHealth, "")
	if got := onPath.Header().Get("Deprecation"); got != "true" {
		t.Fatalf("deprecated route missing Deprecation header, got %q", got)
	}
	if got := onPath.Header().Get("Link"); got != `<https://example.com/migrate>; rel="sunset"` {
		t.Fatalf("Link header = %q", got)
	}

	offPath := avDo(h, http.MethodGet, PathReadyz, "")
	if got := offPath.Header().Get("Deprecation"); got != "" {
		t.Fatalf("non-deprecated route must not carry Deprecation header, got %q", got)
	}
}

func TestServer_APIVersionPreview_Route(t *testing.T) {
	s := NewServer(WithAPIVersionPreview(), WithAPIVersioning("v1"))
	h := s.Handler()

	rec := avDo(h, http.MethodGet, "/api/v2alpha/version", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v2alpha/version = %d, want 200", rec.Code)
	}
	var body struct {
		APIVersion        string   `json:"api_version"`
		Stability         string   `json:"stability"`
		SupportedVersions []string `json:"supported_versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body.APIVersion != "v2alpha" || body.Stability != "preview" {
		t.Fatalf("body = %+v, want api_version=v2alpha stability=preview", body)
	}
	if len(body.SupportedVersions) != 1 || body.SupportedVersions[0] != "v1" {
		t.Fatalf("supported_versions = %v, want [v1]", body.SupportedVersions)
	}
}
