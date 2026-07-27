package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestRecover_PanickingHandler_Returns500(t *testing.T) {
	logger := spi.NopLogger{}
	handler := Recover(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body: %v", err)
	}
	if body["error"] != "internal_error" {
		t.Fatalf(`expected error="internal_error", got %q`, body["error"])
	}
}

func TestRecover_HealthyHandler_PassesThrough(t *testing.T) {
	logger := spi.NopLogger{}
	handler := Recover(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Body.String() != `{"ok":true}` {
		t.Fatalf("expected body %q, got %q", `{"ok":true}`, w.Body.String())
	}
}

func TestRecover_NilPanic_DoesNotCrash(t *testing.T) {
	logger := spi.NopLogger{}
	handler := Recover(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p *int
		_ = *p // nil dereference
	}))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nil", nil)
	// Must not crash
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for nil deref, got %d", w.Code)
	}
}
