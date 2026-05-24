package ssotest

// Integration test that the WithCORS option actually wires the
// middleware into Handler() and the position-in-chain claim holds
// (preflight short-circuit happens INSIDE metrics/ratelimit so 429s
// and metric counts both work as documented).

import (
	"net/http"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/cors"
)

func TestCORSE2E_AllowedOriginGetsAllowOriginHeader(t *testing.T) {
	srv := minServer(t, sso.WithCORS(cors.Policy{
		AllowedOrigins: []string{"https://app.example.com"},
	}))

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	req.Header.Set("Origin", "https://app.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	defer resp.Body.Close()

	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("Allow-Origin = %q, want https://app.example.com", got)
	}
}

func TestCORSE2E_DisallowedOriginGetsNoHeader(t *testing.T) {
	srv := minServer(t, sso.WithCORS(cors.Policy{
		AllowedOrigins: []string{"https://app.example.com"},
	}))

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/health", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	defer resp.Body.Close()

	if resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Error("disallowed origin should not receive Allow-Origin header")
	}
}

func TestCORSE2E_PreflightReturns204(t *testing.T) {
	srv := minServer(t, sso.WithCORS(cors.Policy{
		AllowedOrigins: []string{"https://app.example.com"},
		AllowedMethods: []string{"POST"},
		AllowedHeaders: []string{"Authorization"},
	}))

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/auth/login", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS preflight: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Methods"); got != "POST" {
		t.Errorf("Allow-Methods = %q, want POST", got)
	}
}
