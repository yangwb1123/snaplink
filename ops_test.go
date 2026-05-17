package sso_test

// Tests for the operational surface added in the ops-hardening commit:
//   * /livez always 200
//   * /readyz aggregates registered ReadyChecks and flips to 503 on
//     any failure
//   * /livez + /readyz bypass rate limiting (kubelet probes must
//     never get 429'd) and body limiting
//   * WithBodyLimit returns 413 on oversized requests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/ratelimit"
)

// minServer builds the smallest viable Server for ops tests — no
// authenticator / clients / users / etc. since the ops endpoints
// don't touch those.
func minServer(t *testing.T, opts ...sso.Option) *httptest.Server {
	t.Helper()
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestLivez_AlwaysOK(t *testing.T) {
	srv := minServer(t)

	resp, err := http.Get(srv.URL + "/livez")
	if err != nil {
		t.Fatalf("GET /livez: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"alive"`) {
		t.Errorf("body = %s, want status:alive", body)
	}
}

func TestReadyz_NoChecks_AlwaysReady(t *testing.T) {
	srv := minServer(t)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("no-checks readyz = %d, want 200", resp.StatusCode)
	}
}

func TestReadyz_AllChecksPass_Returns200(t *testing.T) {
	srv := minServer(t,
		sso.WithReadyCheck("db", func(_ context.Context) error { return nil }),
		sso.WithReadyCheck("etcd", func(_ context.Context) error { return nil }),
	)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("all-pass readyz = %d, want 200", resp.StatusCode)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Status != "ready" {
		t.Errorf("status = %q, want ready", body.Status)
	}
	if body.Checks["db"] != "ok" || body.Checks["etcd"] != "ok" {
		t.Errorf("checks = %v, want both ok", body.Checks)
	}
}

func TestReadyz_OneCheckFails_Returns503(t *testing.T) {
	srv := minServer(t,
		sso.WithReadyCheck("db", func(_ context.Context) error { return nil }),
		sso.WithReadyCheck("etcd", func(_ context.Context) error { return errors.New("connection refused") }),
	)
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("one-fail readyz = %d, want 503", resp.StatusCode)
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Status != "unready" {
		t.Errorf("status = %q, want unready", body.Status)
	}
	if body.Checks["db"] != "ok" {
		t.Errorf("db check leaked failure: %v", body.Checks)
	}
	if !strings.Contains(body.Checks["etcd"], "connection refused") {
		t.Errorf("etcd error not surfaced: %v", body.Checks["etcd"])
	}
}

func TestLivezReadyz_BypassRateLimit(t *testing.T) {
	// The critical contract — kubelet probes hit /livez and /readyz
	// every few seconds. Rate-limiting them would cause kubelet to
	// fail the probe and restart the pod under load. They MUST
	// bypass the middleware.
	tight := ratelimit.NewMemoryLimiter(0.001, 1) // effectively 1 then deny forever
	srv := minServer(t, sso.WithRateLimit(ratelimit.Policy{
		Default: tight,
		Key:     func(_ *http.Request) string { return "fixed" },
	}))

	// Exhaust the bucket with N livez probes — none must 429.
	for range 20 {
		resp, err := http.Get(srv.URL + "/livez")
		if err != nil {
			t.Fatalf("GET /livez: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/livez status = %d under rate-limit (must bypass!)", resp.StatusCode)
		}
	}
	for range 20 {
		resp, _ := http.Get(srv.URL + "/readyz")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/readyz status = %d under rate-limit (must bypass!)", resp.StatusCode)
		}
	}
}

func TestBodyLimit_RejectsByContentLength(t *testing.T) {
	srv := minServer(t, sso.WithBodyLimit(100))

	// 200-byte body, Content-Length set — fast-reject before alloc.
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(bytes.Repeat([]byte("x"), 200)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"error":"payload_too_large"`) {
		t.Errorf("body = %s", body)
	}
}

func TestBodyLimit_AcceptsSmallBody(t *testing.T) {
	srv := minServer(t, sso.WithBodyLimit(10000))
	// 50-byte body, well under limit — should at least get past the
	// limit middleware (the handler may error 400 / 401 for other
	// reasons, but NOT 413).
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader([]byte(`{"provider":"none"}`)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		t.Errorf("small body wrongly rejected as too large")
	}
}
