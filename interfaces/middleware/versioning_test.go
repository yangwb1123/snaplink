package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func passthroughHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestDeprecation_Unconfigured_NoHeaders(t *testing.T) {
	h := Deprecation(DeprecationConfig{})(passthroughHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil))

	if v := rec.Header().Get("Deprecation"); v != "" {
		t.Errorf("Deprecation header = %q, want empty (unconfigured must be byte-identical)", v)
	}
	if v := rec.Header().Get("Sunset"); v != "" {
		t.Errorf("Sunset header = %q, want empty", v)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (Deprecation never rejects)", rec.Code)
	}
}

func TestDeprecation_Global(t *testing.T) {
	sunset := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	h := Deprecation(DeprecationConfig{Global: &DeprecationPolicy{Sunset: sunset, Link: "https://example.com/migrate"}})(passthroughHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anywhere", nil))

	if got := rec.Header().Get("Deprecation"); got != "true" {
		t.Errorf("Deprecation = %q, want %q", got, "true")
	}
	wantSunset := sunset.Format(http.TimeFormat)
	if got := rec.Header().Get("Sunset"); got != wantSunset {
		t.Errorf("Sunset = %q, want %q", got, wantSunset)
	}
	if got := rec.Header().Get("Link"); got != `<https://example.com/migrate>; rel="sunset"` {
		t.Errorf("Link = %q", got)
	}
}

func TestDeprecation_Since(t *testing.T) {
	since := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	h := Deprecation(DeprecationConfig{Global: &DeprecationPolicy{Since: since}})(passthroughHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	want := since.Format(http.TimeFormat)
	if got := rec.Header().Get("Deprecation"); got != want {
		t.Errorf("Deprecation = %q, want %q", got, want)
	}
}

func TestDeprecation_RouteSpecific(t *testing.T) {
	cfg := DeprecationConfig{
		Routes: map[string]DeprecationPolicy{
			"/old/exact":  {},
			"/old/group/": {Link: "https://example.com/group"},
		},
	}
	h := Deprecation(cfg)(passthroughHandler())

	cases := []struct {
		path       string
		wantHeader bool
	}{
		{"/old/exact", true},
		{"/old/group/anything", true},
		{"/unrelated", false},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		got := rec.Header().Get("Deprecation") != ""
		if got != c.wantHeader {
			t.Errorf("path %q: Deprecation header present = %v, want %v", c.path, got, c.wantHeader)
		}
	}
}

func TestDeprecation_GlobalAndRoute_RouteWins(t *testing.T) {
	cfg := DeprecationConfig{
		Global: &DeprecationPolicy{Link: "https://example.com/global"},
		Routes: map[string]DeprecationPolicy{"/special": {Link: "https://example.com/special"}},
	}
	h := Deprecation(cfg)(passthroughHandler())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/special", nil))
	if got := rec.Header().Get("Link"); got != `<https://example.com/special>; rel="sunset"` {
		t.Errorf("route-specific policy did not win: Link = %q", got)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/other", nil))
	if got := rec2.Header().Get("Link"); got != `<https://example.com/global>; rel="sunset"` {
		t.Errorf("global policy did not apply: Link = %q", got)
	}
}

func TestAcceptVersion_Unconfigured_NoOp(t *testing.T) {
	h := AcceptVersion(AcceptVersionConfig{})(passthroughHandler())

	for _, hdr := range []string{"", "v1", "bogus"} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		if hdr != "" {
			req.Header.Set("Accept-Version", hdr)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Accept-Version=%q: status = %d, want 200 (negotiation disabled must be a no-op)", hdr, rec.Code)
		}
	}
}

func TestAcceptVersion_NoHeader_Passthrough(t *testing.T) {
	h := AcceptVersion(AcceptVersionConfig{Supported: []string{"v1", "v2alpha"}})(passthroughHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("no Accept-Version header: status = %d, want 200 (today's behavior unchanged)", rec.Code)
	}
}

func TestAcceptVersion_Supported_Passthrough(t *testing.T) {
	h := AcceptVersion(AcceptVersionConfig{Supported: []string{"v1", "v2alpha"}})(passthroughHandler())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Version", "v2alpha")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for a supported version", rec.Code)
	}
}

func TestAcceptVersion_Unsupported_Rejected(t *testing.T) {
	h := AcceptVersion(AcceptVersionConfig{Supported: []string{"v1"}})(passthroughHandler())
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept-Version", "v99")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if got := rec.Body.String(); !strings.Contains(got, `"unsupported_version"`) {
		t.Errorf("body = %q, want it to contain the unsupported_version error code", got)
	}
}
