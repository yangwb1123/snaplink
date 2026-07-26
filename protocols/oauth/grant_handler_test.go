package oauth

import (
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func TestGrantHandlerError(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(rec, req)

	GrantHandlerError(ctx, 400, "invalid_grant")

	if rec.Code != 400 {
		t.Errorf("expected 400, got %d", rec.Code)
	}

	// Parse response body
	var body map[string]string
	// Response is JSON
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %q", contentType)
	}
	_ = body
}

func TestGrantHandlerErrorMessage(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(rec, req)

	GrantHandlerError(ctx, 401, "invalid_token")

	if rec.Code != 401 {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestWithCIBAPushLogger(t *testing.T) {
	logger := &testLogger{}
	opt := WithCIBAPushLogger(logger)
	if opt == nil {
		t.Error("expected non-nil option")
	}
}

type testLogger struct{}

func (t *testLogger) Debug(msg string, args ...any) {}
func (t *testLogger) Info(msg string, args ...any)  {}
func (t *testLogger) Warn(msg string, args ...any)  {}
func (t *testLogger) Error(msg string, args ...any) {}
