package sso_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestLogoutAlwaysNoStore(t *testing.T) {
	srv := sso.NewServer()
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"missing credentials", `{}`, http.StatusBadRequest},
		{"invalid JSON", `{`, http.StatusBadRequest},
		{"unknown session", `{"session_id":"unknown-fixture-session"}`, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, sso.PathLogout, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			srv.Handler().ServeHTTP(response, req)
			if response.Code != tc.status {
				t.Fatalf("status=%d, want %d", response.Code, tc.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Pragma") != "no-cache" {
				t.Fatal("logout response is cacheable")
			}
		})
	}
}
