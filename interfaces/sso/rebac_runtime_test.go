package sso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
)

func TestReBACRuntimeIsWiredIntoReadiness(t *testing.T) {
	engine := rebac.NewEngine(rebac.NewMemoryStore())
	srv := NewServer(WithRebacEngine(engine))
	runtime := engine.HotRuntime()
	if runtime == nil {
		t.Fatal("ReBAC hot runtime was not created")
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })
	handler := srv.Handler()
	assertReadyStatus(t, handler, http.StatusOK)

	if err := runtime.Disable(context.Background()); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	assertReadyStatus(t, handler, http.StatusServiceUnavailable)
	if err := runtime.Activate(context.Background()); err != nil {
		t.Fatalf("Activate: %v", err)
	}
	assertReadyStatus(t, handler, http.StatusOK)
}

func assertReadyStatus(t *testing.T, handler http.Handler, want int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("/readyz status = %d, want %d; body=%s", rec.Code, want, rec.Body.String())
	}
}
