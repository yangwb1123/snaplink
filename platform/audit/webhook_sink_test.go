package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

func TestWebhookSink_PostsJSON(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		received []audit.Event
		hdrSeen  http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer func() { _ = r.Body.Close() }()
		var e audit.Event
		if err := json.Unmarshal(body, &e); err != nil {
			t.Errorf("bad JSON: %v", err)
		}
		mu.Lock()
		received = append(received, e)
		hdrSeen = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL,
		audit.WithWebhookHeader("X-Audit-Token", "secret"),
	)

	err := s.Record(context.Background(), &audit.Event{
		Type: audit.EventLogin, ActorID: "alice", RequestID: "r-1",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 event received, got %d", len(received))
	}
	if received[0].ActorID != "alice" || received[0].RequestID != "r-1" {
		t.Errorf("event mismatch: %+v", received[0])
	}
	if hdrSeen.Get("Content-Type") != "application/json" {
		t.Errorf("missing Content-Type")
	}
	if hdrSeen.Get("X-Audit-Token") != "secret" {
		t.Errorf("custom header not propagated")
	}
}

func TestWebhookSink_4xxReturnsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL)
	err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err == nil {
		t.Fatal("expected error on 4xx response")
	}
}

func TestWebhookSink_GetAndQueryWriteOnly(t *testing.T) {
	t.Parallel()
	s := audit.NewWebhookSink("http://nope.invalid")
	if _, err := s.Get(context.Background(), "x"); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Get: expected ErrSinkWriteOnly, got %v", err)
	}
	if _, err := s.Query(context.Background(), audit.Query{}); !errors.Is(err, audit.ErrSinkWriteOnly) {
		t.Errorf("Query: expected ErrSinkWriteOnly, got %v", err)
	}
}

func TestWebhookSink_OptionsApplyCleanly(t *testing.T) {
	t.Parallel()
	// Smoke: every Option must construct without panic. Behavior of the
	// final wired client is exercised below in NetworkErrorPropagates.
	custom := &http.Client{Timeout: 250 * time.Millisecond}
	_ = audit.NewWebhookSink("http://localhost",
		audit.WithWebhookTimeout(100*time.Millisecond),
		audit.WithWebhookHTTPClient(custom),
		audit.WithWebhookHTTPClient(nil), // nil ignored — does not blow away earlier client
	)
}

func TestWebhookSink_NetworkErrorPropagates(t *testing.T) {
	t.Parallel()
	// Bind a port then immediately close it. Subsequent POSTs to that address
	// fail at the transport layer — covers WebhookSink.Record's error branch
	// without depending on httptest connection lifecycle.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	s := audit.NewWebhookSink("http://"+addr,
		audit.WithWebhookTimeout(500*time.Millisecond),
	)
	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err == nil {
		t.Fatal("expected network error")
	}
}
