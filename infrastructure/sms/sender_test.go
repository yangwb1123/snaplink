package sms

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testConfig(baseURL string) Config {
	return Config{
		AccountSID: "AC_test_sid",
		AuthToken:  "test-auth-token",
		FromNumber: "+15005550006",
		BaseURL:    baseURL,
	}
}

// TestSender_Send_PostsExpectedRequest proves a real HTTP round trip against
// an httptest.Server: the request lands on Twilio's documented Messages
// resource path, carries HTTP Basic Auth (AccountSID/AuthToken), and posts a
// form-encoded To/From/Body body with the code substituted into the
// template.
func TestSender_Send_PostsExpectedRequest(t *testing.T) {
	t.Parallel()
	var (
		gotPath   string
		gotUser   string
		gotPass   string
		gotOK     bool
		gotTo     string
		gotFrom   string
		gotBody   string
		gotMethod string
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotUser, gotPass, gotOK = r.BasicAuth()
		if err := r.ParseForm(); err != nil {
			t.Errorf("server: parse form: %v", err)
		}
		gotTo = r.PostForm.Get(formFieldTo)
		gotFrom = r.PostForm.Get(formFieldFrom)
		gotBody = r.PostForm.Get(formFieldBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	cfg := testConfig(ts.URL)
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Send(context.Background(), "+15551234567", "482913"); err != nil {
		t.Fatalf("Send: %v", err)
	}

	wantPath := fmt.Sprintf(messagesPathTemplate, cfg.AccountSID)
	if gotPath != wantPath {
		t.Errorf("path = %q, want %q", gotPath, wantPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if !gotOK || gotUser != cfg.AccountSID || gotPass != cfg.AuthToken {
		t.Errorf("basic auth = (%q, %q, ok=%v), want (%q, %q, true)", gotUser, gotPass, gotOK, cfg.AccountSID, cfg.AuthToken)
	}
	if gotTo != "+15551234567" {
		t.Errorf("To = %q, want +15551234567", gotTo)
	}
	if gotFrom != cfg.FromNumber {
		t.Errorf("From = %q, want %q", gotFrom, cfg.FromNumber)
	}
	if !strings.Contains(gotBody, "482913") {
		t.Errorf("Body = %q, want it to contain the code 482913", gotBody)
	}
}

// TestSender_Send_CustomMessageTemplate proves MessageTemplate substitution
// replaces every occurrence of the {code} placeholder.
func TestSender_Send_CustomMessageTemplate(t *testing.T) {
	t.Parallel()
	var gotBody string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotBody = r.PostForm.Get(formFieldBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	cfg := testConfig(ts.URL)
	cfg.MessageTemplate = "code={code} (expires soon)"
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Send(context.Background(), "+15551234567", "000111"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if want := "code=000111 (expires soon)"; gotBody != want {
		t.Errorf("Body = %q, want %q", gotBody, want)
	}
}

// TestSender_Send_NonSuccessStatusIsError proves a non-2xx response surfaces
// as an error, and that the error never echoes the response body — the
// oracle-leak-hardening property Sender.Send's doc comment calls out (a
// provider error payload can carry account-identifying detail).
func TestSender_Send_NonSuccessStatusIsError(t *testing.T) {
	t.Parallel()
	const secretLeak = "super-secret-account-detail-should-never-surface"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(secretLeak))
	}))
	defer ts.Close()

	s, err := New(testConfig(ts.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.Send(context.Background(), "+15551234567", "123456")
	if err == nil {
		t.Fatal("expected an error for a non-2xx response")
	}
	if strings.Contains(err.Error(), secretLeak) {
		t.Fatalf("error leaked the raw response body: %v", err)
	}
}

// TestSender_Send_RespectsContextCancellation proves Send honors ctx via
// http.NewRequestWithContext rather than blocking past cancellation.
func TestSender_Send_RespectsContextCancellation(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until this test unblocks it below
	}))
	// Defer order matters here: httptest.Server.Close() blocks until every
	// in-flight handler goroutine has returned, but the handler above only
	// returns once block is closed. Declaring close(block) AFTER ts.Close()
	// makes it run FIRST (defers are LIFO) — unblocking the handler so
	// Close() can actually complete instead of deadlocking against itself.
	defer ts.Close()
	defer close(block)

	s, err := New(testConfig(ts.URL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- s.Send(ctx, "+15551234567", "123456") }()
	select {
	case sendErr := <-done:
		if sendErr == nil {
			t.Fatal("expected an error when the context deadline elapses")
		}
	case <-time.After(15 * time.Second):
		// Generous relative to the 50ms ctx deadline — this only guards
		// against Send truly ignoring ctx, not against scheduler jitter
		// under -race / heavy concurrent load (observed to matter in CI-like
		// conditions with many parallel `go test -race` processes).
		t.Fatal("Send did not respect ctx cancellation/timeout")
	}
}

// TestNew_MissingRequiredFieldsErrors proves each required field is
// validated at construction — a misconfigured "http" provider must fail
// loud rather than silently drop deliveries at Send time.
func TestNew_MissingRequiredFieldsErrors(t *testing.T) {
	t.Parallel()
	base := testConfig("https://example.invalid")
	tests := []struct {
		name string
		cfg  Config
	}{
		{"missing account sid", Config{AuthToken: base.AuthToken, FromNumber: base.FromNumber}},
		{"missing auth token", Config{AccountSID: base.AccountSID, FromNumber: base.FromNumber}},
		{"missing from number", Config{AccountSID: base.AccountSID, AuthToken: base.AuthToken}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(tt.cfg); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

// TestNew_DefaultsAppliedWhenUnset proves the optional fields (template,
// timeout, base URL) fall back to sane defaults rather than zero values
// that would break Send (e.g. a zero-timeout http.Client blocking forever).
func TestNew_DefaultsAppliedWhenUnset(t *testing.T) {
	t.Parallel()
	s, err := New(Config{AccountSID: "AC1", AuthToken: "tok", FromNumber: "+15005550006"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.cfg.MessageTemplate != defaultMessageTemplate {
		t.Errorf("MessageTemplate = %q, want default %q", s.cfg.MessageTemplate, defaultMessageTemplate)
	}
	if s.cfg.HTTPTimeout != defaultHTTPTimeout {
		t.Errorf("HTTPTimeout = %v, want default %v", s.cfg.HTTPTimeout, defaultHTTPTimeout)
	}
	if s.cfg.BaseURL != defaultBaseURL {
		t.Errorf("BaseURL = %q, want default %q", s.cfg.BaseURL, defaultBaseURL)
	}
	if s.client.Timeout != defaultHTTPTimeout {
		t.Errorf("client.Timeout = %v, want %v", s.client.Timeout, defaultHTTPTimeout)
	}
}
