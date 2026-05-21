package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/config"
)

func TestBuildApp_AuditWebhookRequiresURL(t *testing.T) {
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Webhook.Enabled = true
	// URL omitted on purpose.

	_, err := buildApp(cfg, quietLogger())
	if err == nil {
		t.Fatal("expected error when audit.webhook.enabled with no URL")
	}
}

func TestBuildApp_AuditWebhookFansOutAlongsideMemory(t *testing.T) {
	// Spin a collector that captures every POST; cfg points the
	// webhook sink at it. Record one event via the recorder; both
	// the memory query layer AND the webhook should see it.
	received := make(chan map[string]any, 4)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(body, &ev)
		received <- ev
		w.WriteHeader(http.StatusNoContent)
	}))
	defer collector.Close()

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.URL = collector.URL
	cfg.Audit.Webhook.Timeout = 2 * time.Second
	cfg.Audit.Webhook.Headers = map[string]string{"Authorization": "Bearer test"}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	if a.recorder == nil {
		t.Fatal("recorder nil")
	}

	a.recorder.Record(context.Background(), &audit.Event{
		Type:    audit.EventLogin,
		ActorID: "user-1",
	})

	select {
	case ev := <-received:
		if ev["actor_id"] != "user-1" {
			t.Fatalf("webhook actor_id: %v want user-1", ev["actor_id"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never received event")
	}
}

func TestBuildApp_AuditWebhookRetriesTransientFailures(t *testing.T) {
	// First request fails (500), second succeeds. Webhook sink should
	// retry without dropping the event.
	var attempts atomic.Int32
	done := make(chan struct{})
	var once sync.Once
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		once.Do(func() { close(done) })
	}))
	defer collector.Close()

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.URL = collector.URL
	cfg.Audit.Webhook.Retry.MaxAttempts = 3
	cfg.Audit.Webhook.Retry.InitialBackoff = 10 * time.Millisecond
	cfg.Audit.Webhook.Retry.MaxBackoff = 50 * time.Millisecond

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-r"})

	select {
	case <-done:
		// Confirm we did retry, not just succeed on first try.
		if got := attempts.Load(); got < 2 {
			t.Fatalf("attempts = %d want >= 2 (retry path not exercised)", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("webhook never succeeded after retries; attempts=%d", attempts.Load())
	}
}

func TestBuildApp_AuditWebhookComposesWithAsync(t *testing.T) {
	// Verify async wrap fires when both async.enabled and
	// webhook.enabled — the worker drains via MultiSink to both
	// memory and webhook.
	received := make(chan struct{}, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		select {
		case received <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer collector.Close()

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Async.Enabled = true
	cfg.Audit.Async.BufferSize = 16
	cfg.Audit.Async.Workers = 1
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.URL = collector.URL

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()
	defer a.auditAsyncSink.Close(context.Background())

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-a"})

	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never received async-dispatched event")
	}
}

func TestBuildApp_AuditWebhookHeaderPropagation(t *testing.T) {
	got := make(chan http.Header, 1)
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Clone():
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer collector.Close()

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.URL = collector.URL
	cfg.Audit.Webhook.Headers = map[string]string{
		"Authorization": "Bearer s3cret",
		"X-Tenant":      "acme",
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer a.registry.Close()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "u"})

	select {
	case h := <-got:
		if h.Get("Authorization") != "Bearer s3cret" {
			t.Fatalf("Authorization header: got %q want Bearer s3cret", h.Get("Authorization"))
		}
		if h.Get("X-Tenant") != "acme" {
			t.Fatalf("X-Tenant header: got %q want acme", h.Get("X-Tenant"))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never received event")
	}
}
