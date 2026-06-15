package sso

import (
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/core"
)

func TestHandleHealth(t *testing.T) {
	t.Parallel()

	s := &Server{
		issuer: "https://sso.example.com",
	}
	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)
	s.handleHealth(ctx)

	if w.Code != 200 {
		t.Errorf("handleHealth status = %d, want 200", w.Code)
	}
}

func TestHandleHealthWithIssuer(t *testing.T) {
	t.Parallel()

	s := &Server{
		issuer: "https://sso.example.com",
	}
	r := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)
	s.handleHealth(ctx)

	if w.Code != 200 {
		t.Errorf("handleHealth status = %d, want 200", w.Code)
	}
}

func TestBearerToken(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer mytoken123")
	if got := bearerToken(r); got != "mytoken123" {
		t.Errorf("bearerToken() = %q, want mytoken123", got)
	}

	// No Authorization header
	r2 := httptest.NewRequest("GET", "/", nil)
	if got := bearerToken(r2); got != "" {
		t.Errorf("bearerToken() without header = %q, want empty", got)
	}
}

func TestErrorBody(t *testing.T) {
	t.Parallel()

	m := errorBody("invalid_request")
	if m["error"] != "invalid_request" {
		t.Errorf("errorBody() = %v, want error=invalid_request", m)
	}
}
