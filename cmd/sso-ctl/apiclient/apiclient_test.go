package apiclient

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordingServer records requests for contract assertions.
type recordingServer struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (r *recordingServer) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req.Clone(req.Context()))
}

func (r *recordingServer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// TestDo_BearerHeader pins the auth contract the sweep depends on: the
// Authorization header is present exactly when a token is configured
// (option or env), and absent otherwise. The env is force-unset so the
// test never depends on the runner's environment.
func TestDo_BearerHeader(t *testing.T) {
	t.Setenv(EnvToken, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	with := New(WithAddr(srv.URL), WithToken("tok-123"))
	resp, err := with.Get("/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Request.Header.Get("Authorization"); got != "Bearer tok-123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer tok-123")
	}

	without := New(WithAddr(srv.URL))
	resp, err = without.Get("/x")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if got := resp.Request.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization = %q, want empty (no token configured)", got)
	}
}

// TestDo_JSONHeaders pins the content negotiation the server-side
// BindParams relies on: body-bearing requests send Content-Type
// application/json, and every request sends Accept application/json.
func TestDo_JSONHeaders(t *testing.T) {
	t.Setenv(EnvToken, "")
	var gotCT, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotCT = req.Header.Get("Content-Type")
		gotAccept = req.Header.Get("Accept")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New(WithAddr(srv.URL))
	resp, err := c.Post("/token", map[string]string{"grant_type": "client_credentials"})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}

	resp, err = c.Get("/jwks")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if gotCT != "" {
		t.Errorf("GET Content-Type = %q, want empty", gotCT)
	}
	if gotAccept != "application/json" {
		t.Errorf("GET Accept = %q, want application/json", gotAccept)
	}
}

// TestNew_OptionEnvPrecedence pins New's resolution order, which the
// --addr/SSO_ADMIN_ADDR effective-addr preflight mirrors: the token option
// wins over the env token; the env addr wins over the WithAddr option.
func TestNew_OptionEnvPrecedence(t *testing.T) {
	t.Setenv(EnvToken, "env-token")
	t.Setenv(EnvAddr, "http://env.invalid")

	c := New(WithToken("opt-token"))
	if c.token != "opt-token" {
		t.Errorf("token = %q, want option to win over env", c.token)
	}
	c = New()
	if c.token != "env-token" {
		t.Errorf("token = %q, want env fallback", c.token)
	}
	c = New(WithAddr("http://opt.invalid"))
	if c.baseURL != "http://env.invalid" {
		t.Errorf("baseURL = %q, want env addr to win over option", c.baseURL)
	}
}

// TestNew_NoRedirect pins the WithNoRedirect contract: the option stops the
// client at the 3xx response (target receives zero requests), while the
// default client still follows — existing subcommands' behavior is untouched.
func TestNew_NoRedirect(t *testing.T) {
	t.Setenv(EnvToken, "")
	var mu sync.Mutex
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		targetHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	noFollow := New(WithAddr(redirector.URL), WithNoRedirect())
	resp, err := noFollow.Get("/hop")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, rerr := ReadBody(resp)
	if rerr != nil {
		t.Fatalf("ReadBody: %v", rerr)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want 302 observed without following", resp.StatusCode)
	}
	if len(body) == 0 {
		t.Error("body unreadable — ErrUseLastResponse 3xx bodies must stay drainable")
	}
	mu.Lock()
	hits := targetHits
	mu.Unlock()
	if hits != 0 {
		t.Errorf("redirect target received %d requests, want 0 under WithNoRedirect", hits)
	}

	follow := New(WithAddr(redirector.URL))
	resp, err = follow.Get("/hop")
	if err != nil {
		t.Fatalf("GET (default follow): %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("default client status = %d, want 200 after following", resp.StatusCode)
	}
}

// TestWithNoRedirect_StopsFollowing pins the 307/308 body-exfiltration
// vector: a 307 mint redirect must never forward the POST body to the
// target.
func TestWithNoRedirect_StopsFollowing(t *testing.T) {
	t.Setenv(EnvToken, "")
	var mu sync.Mutex
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		targetHits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	c := New(WithAddr(redirector.URL), WithNoRedirect())
	resp, err := c.Post("/token", map[string]string{"client_secret": "TOPSECRET"})
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("status = %d, want 307 observed without following", resp.StatusCode)
	}
	mu.Lock()
	hits := targetHits
	mu.Unlock()
	if hits != 0 {
		t.Errorf("307 target received %d requests — POST body would have been forwarded", hits)
	}
}

// TestReadBody_CapAndClose pins the ReadBody contract: 1MB cap and the body
// is always closed.
func TestReadBody_CapAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(strings.Repeat("x", 2<<20))) // 2MB
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, err := ReadBody(resp)
	if err != nil {
		t.Fatalf("ReadBody: %v", err)
	}
	if len(body) != 1<<20 {
		t.Errorf("ReadBody len = %d, want 1MB cap", len(body))
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Error("resp.Body still open after ReadBody")
	}
}

// TestDo_Non2xxNoErrorMapping pins that Do returns the raw response for
// non-2xx statuses (the sweep inspects statuses itself).
func TestDo_Non2xxNoErrorMapping(t *testing.T) {
	t.Setenv(EnvToken, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer srv.Close()

	resp, err := New(WithAddr(srv.URL)).Get("/missing")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, rerr := ReadBody(resp)
	if rerr != nil {
		t.Fatalf("ReadBody: %v", rerr)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 surfaced as-is", resp.StatusCode)
	}
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil || out["error"] != "not_found" {
		t.Errorf("body = %q, want decodable error body", body)
	}
}
