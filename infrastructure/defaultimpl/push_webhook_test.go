package defaultimpl_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
)

func TestHTTPWebhookPushTransport_RejectsEmptyURL(t *testing.T) {
	t.Parallel()
	_, err := defaultimpl.NewHTTPWebhookPushTransport("")
	if err == nil {
		t.Fatal("want error for empty URL")
	}
}

func TestHTTPWebhookPushTransport_SendsJSONPayload(t *testing.T) {
	t.Parallel()
	var received pushWebhookReceived
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received.body)
		received.bearer = r.Header.Get("Authorization")
		received.contentType = r.Header.Get("Content-Type")
		received.calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := defaultimpl.NewHTTPWebhookPushTransport(srv.URL,
		defaultimpl.WithPushWebhookBearerToken("op-token"),
		defaultimpl.WithPushWebhookHeader("X-Operator", "internal"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = tr.Send(context.Background(), "ch-123", "alice", map[string]string{"client": "web"})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if received.calls.Load() != 1 {
		t.Fatalf("server called %d times, want 1", received.calls.Load())
	}
	if received.body["approval_id"] != "ch-123" {
		t.Errorf("approval_id = %v, want ch-123", received.body["approval_id"])
	}
	if received.body["subject_id"] != "alice" {
		t.Errorf("subject_id = %v, want alice", received.body["subject_id"])
	}
	meta, _ := received.body["metadata"].(map[string]any)
	if meta["client"] != "web" {
		t.Errorf("metadata.client = %v, want web", meta["client"])
	}
	if received.bearer != "Bearer op-token" {
		t.Errorf("Authorization = %q, want Bearer op-token", received.bearer)
	}
	if received.contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", received.contentType)
	}
}

func TestHTTPWebhookPushTransport_RetriesOn5xx(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			http.Error(w, "transient", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, _ := defaultimpl.NewHTTPWebhookPushTransport(srv.URL,
		defaultimpl.WithPushWebhookRetry(5, 10*time.Millisecond, 100*time.Millisecond),
	)
	if err := tr.Send(context.Background(), "ch-r", "alice", nil); err != nil {
		t.Fatalf("Send (should succeed on 3rd attempt): %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3 (two 503s + one 200)", calls.Load())
	}
}

func TestHTTPWebhookPushTransport_GivesUpAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	tr, _ := defaultimpl.NewHTTPWebhookPushTransport(srv.URL,
		defaultimpl.WithPushWebhookRetry(3, 10*time.Millisecond, 30*time.Millisecond),
	)
	err := tr.Send(context.Background(), "ch", "alice", nil)
	if err == nil {
		t.Fatal("want error after max attempts")
	}
	if !strings.Contains(err.Error(), "3 attempts") {
		t.Errorf("error should mention attempt count: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

func TestHTTPWebhookPushTransport_RespectsContextCancelBetweenRetries(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	tr, _ := defaultimpl.NewHTTPWebhookPushTransport(srv.URL,
		defaultimpl.WithPushWebhookRetry(10, 100*time.Millisecond, 1*time.Second),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := tr.Send(ctx, "ch", "alice", nil)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("want error from canceled context")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Send took %v with 150ms timeout — backoff didn't honor ctx", elapsed)
	}
}

func TestHTTPWebhookPushTransport_AcceptsAllStatusesIn2xx(t *testing.T) {
	t.Parallel()
	for _, code := range []int{200, 201, 202, 204} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(code)
			}))
			defer srv.Close()
			tr, _ := defaultimpl.NewHTTPWebhookPushTransport(srv.URL)
			if err := tr.Send(context.Background(), "ch", "alice", nil); err != nil {
				t.Errorf("status %d: %v", code, err)
			}
		})
	}
}

func TestHTTPWebhookPushTransport_OmitsAuthorizationWhenNoToken(t *testing.T) {
	t.Parallel()
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr, _ := defaultimpl.NewHTTPWebhookPushTransport(srv.URL)
	_ = tr.Send(context.Background(), "ch", "alice", nil)
	if seenAuth != "" {
		t.Errorf("Authorization sent without token: %q", seenAuth)
	}
}

func TestHTTPWebhookPushTransport_MultipleHeadersAccumulate(t *testing.T) {
	t.Parallel()
	var seen http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tr, _ := defaultimpl.NewHTTPWebhookPushTransport(srv.URL,
		defaultimpl.WithPushWebhookHeader("X-A", "1"),
		defaultimpl.WithPushWebhookHeader("X-B", "2"),
	)
	_ = tr.Send(context.Background(), "ch", "alice", nil)
	if seen.Get("X-A") != "1" || seen.Get("X-B") != "2" {
		t.Errorf("custom headers missing: %v", seen)
	}
}

// pushWebhookReceived collects what the server saw across a test —
// concurrent-safe via the atomic counter; body+headers written once
// since each test runs sequentially.
type pushWebhookReceived struct {
	calls       atomic.Int32
	body        map[string]any
	bearer      string
	contentType string
}
