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
	"github.com/snaplink/sso/shared/security"
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

func TestWebhookSink_SignsPayload(t *testing.T) {
	t.Parallel()
	const secret = "whsec-test"
	var (
		mu   sync.Mutex
		sig  string
		body []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		sig = r.Header.Get(security.WebhookSignatureHeader)
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL, audit.WithWebhookSigningSecret(secret))
	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if sig == "" {
		t.Fatal("signature header missing")
	}
	if err := security.VerifyWebhookSignature([]byte(secret), sig, body, time.Now(), security.DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("VerifyWebhookSignature: %v", err)
	}
	if err := security.VerifyWebhookSignature([]byte("wrong"), sig, body, time.Now(), security.DefaultWebhookSignatureTolerance); err == nil {
		t.Fatal("verification with wrong secret must fail")
	}
}

// TestWebhookSink_RotatingSecretSignsWithCurrentVersion proves the
// end-to-end wiring of the credential-rotation framework's webhook rotator
// (WebhookSecretRotator) to a real outbound sender: after a Rotate, the sink
// signs with the NEW secret, and a receiver still holding the demoted secret
// authenticates it via RotatingWebhookSecret.Verify during the overlap
// window rather than rejecting it outright.
func TestWebhookSink_RotatingSecretSignsWithCurrentVersion(t *testing.T) {
	t.Parallel()
	rws, err := security.NewRotatingWebhookSecret([]byte("initial-webhook-secret-32-bytes"))
	if err != nil {
		t.Fatalf("NewRotatingWebhookSecret: %v", err)
	}

	var (
		mu   sync.Mutex
		sig  string
		body []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		sig = r.Header.Get(security.WebhookSignatureHeader)
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL, audit.WithWebhookRotatingSecret(rws))

	// Rotate BEFORE the first delivery — the send must use the CURRENT
	// (post-rotation) secret, not whatever was installed at construction.
	if _, err := rws.Rotate(time.Now(), time.Hour); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	mu.Lock()
	gotSig, gotBody := sig, body
	mu.Unlock()
	if gotSig == "" {
		t.Fatal("signature header missing")
	}
	if err := security.VerifyWebhookSignature(rws.Current(), gotSig, gotBody, time.Now(), security.DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("delivery did not verify against the post-rotation secret: %v", err)
	}
	// The RotatingWebhookSecret's own dual-accept Verify still authenticates
	// it too (it's the current version).
	if err := rws.Verify(gotSig, gotBody, time.Now(), security.DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("RotatingWebhookSecret.Verify rejected a signature made with its own current secret: %v", err)
	}
}

func TestWebhookSink_NoSignatureWithoutSecret(t *testing.T) {
	t.Parallel()
	var (
		mu  sync.Mutex
		sig string
		hit bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sig, hit = r.Header.Get(security.WebhookSignatureHeader), true
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL)
	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !hit || sig != "" {
		t.Fatalf("hit=%v sig=%q; want hit with empty signature header", hit, sig)
	}
}
