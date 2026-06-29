package cors_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/cors"
)

// echo200 returns 200 with a trivial body — the test handler the
// middleware wraps.
func echo200() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func TestEmptyPolicy_IsIdentity(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("empty policy must not emit CORS headers")
	}
}

func TestNoOrigin_IsPassthrough(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{AllowedOrigins: []string{"https://app.example.com"}})
	wrapped := mw(echo200())

	// No Origin header — server-to-server request, not a browser CORS check.
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("non-CORS request should not get CORS headers")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestExactOrigin_Allowed(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{
		AllowedOrigins: []string{"https://app.example.com"},
	})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want Origin", got)
	}
}

func TestExactOrigin_Disallowed(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{
		AllowedOrigins: []string{"https://app.example.com"},
	})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	// No CORS headers — browser blocks on its end.
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("disallowed origin got Allow-Origin = %q", got)
	}
	// Handler still runs (server-side doesn't refuse).
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (CORS is browser-enforced)", rec.Code)
	}
}

func TestWildcard_EmitsStar(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{AllowedOrigins: []string{"*"}})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anywhere.example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("wildcard Allow-Origin = %q, want *", got)
	}
}

func TestWildcardWithCredentials_EchoesOrigin(t *testing.T) {
	t.Parallel()
	// CORS spec forbids "*" + credentials. Middleware degrades
	// gracefully by echoing the request Origin instead.
	mw := cors.Middleware(cors.Policy{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: true,
	})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anywhere.example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://anywhere.example.com" {
		t.Errorf("with credentials, expected echoed origin, got %q", got)
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("Allow-Credentials header missing")
	}
}

func TestPreflight_EmitsAllowMethodsAndHeaders(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"GET", "POST", "PATCH"},
		AllowedHeaders: []string{"X-Custom", "Authorization"},
		MaxAge:         time.Hour,
	})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodOptions, "/auth/login", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PATCH" {
		t.Errorf("Allow-Methods = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "X-Custom, Authorization" {
		t.Errorf("Allow-Headers = %q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "3600" {
		t.Errorf("Max-Age = %q, want 3600", got)
	}
}

func TestPreflight_WithoutRequestMethod_NotShortCircuited(t *testing.T) {
	t.Parallel()
	// An OPTIONS request without Access-Control-Request-Method is
	// NOT a CORS preflight — let it through to the underlying handler.
	mw := cors.Middleware(cors.Policy{AllowedOrigins: []string{"*"}})
	called := false
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if !called {
		t.Error("plain OPTIONS should pass to inner handler")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestExposedHeaders(t *testing.T) {
	t.Parallel()
	mw := cors.Middleware(cors.Policy{
		AllowedOrigins: []string{"*"},
		ExposedHeaders: []string{"X-Request-ID", "X-RateLimit-Remaining"},
	})
	wrapped := mw(echo200())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Origin", "https://anywhere.example.com")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Expose-Headers"); got != "X-Request-ID, X-RateLimit-Remaining" {
		t.Errorf("Expose-Headers = %q", got)
	}
}
