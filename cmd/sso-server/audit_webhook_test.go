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

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/security"
)

// subCollector captures webhook deliveries for the subscription tests: the
// event types received and (when signed) the last signature header + raw body
// so a test can verify the HMAC with the Wave-1 receiver-side verifier.
type subCollector struct {
	mu    sync.Mutex
	types []string
	sig   string
	body  []byte
}

func newSubCollector(t *testing.T) (*subCollector, *httptest.Server) {
	t.Helper()
	c := &subCollector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(b, &ev)
		c.mu.Lock()
		if typ, ok := ev["type"].(string); ok {
			c.types = append(c.types, typ)
		}
		if s := r.Header.Get(security.WebhookSignatureHeader); s != "" {
			c.sig, c.body = s, b
		}
		c.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return c, srv
}

func (c *subCollector) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.types...)
}

// With audit.async disabled the recorder drives every sink synchronously
// through the MultiSink, so each webhook POST has completed by the time
// Record returns — no polling needed. These tests rely on that ordering.
func TestBuildApp_AuditWebhookSubscriptionsDisjointDelivery(t *testing.T) {
	t.Parallel()
	const loginSecret = "whsec-login"
	loginC, loginSrv := newSubCollector(t)
	adminC, adminSrv := newSubCollector(t)

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 32
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{
		{Name: "login-only", URL: loginSrv.URL, EventTypes: []string{string(audit.EventLogin)}, SigningSecret: loginSecret},
		{Name: "admin", URL: adminSrv.URL, EventTypes: []string{"admin_" + audit.EventTypeWildcardSuffix}},
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "u"})
	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventAdminClientCreated, ActorID: "admin"})
	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogout, ActorID: "u"})

	if got := loginC.snapshot(); len(got) != 1 || got[0] != string(audit.EventLogin) {
		t.Fatalf("login-only subscription received %v, want [login]", got)
	}
	if got := adminC.snapshot(); len(got) != 1 || got[0] != string(audit.EventAdminClientCreated) {
		t.Fatalf("admin subscription received %v, want [admin_client_created]", got)
	}

	// The login subscription is signed — prove the delivered payload verifies
	// with the Wave-1 receiver-side verifier (and fails under a wrong secret).
	loginC.mu.Lock()
	sig, body := loginC.sig, loginC.body
	loginC.mu.Unlock()
	if sig == "" {
		t.Fatal("login subscription payload not signed")
	}
	if err := security.VerifyWebhookSignature([]byte(loginSecret), sig, body, time.Now(), security.DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("VerifyWebhookSignature: %v", err)
	}
	if err := security.VerifyWebhookSignature([]byte("wrong"), sig, body, time.Now(), security.DefaultWebhookSignatureTolerance); err == nil {
		t.Fatal("verification with wrong secret must fail")
	}
}

func TestBuildApp_AuditWebhookScalarPlusSubscriptionCoexist(t *testing.T) {
	t.Parallel()
	// Legacy scalar url = implicit unfiltered "default" firehose; the
	// explicit subscription filters. Both fan out from the one MultiSink.
	scalarC, scalarSrv := newSubCollector(t)
	filteredC, filteredSrv := newSubCollector(t)

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 32
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.URL = scalarSrv.URL // legacy scalar
	cfg.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{
		{Name: "logins", URL: filteredSrv.URL, EventTypes: []string{string(audit.EventLogin)}},
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "u"})
	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogout, ActorID: "u"})

	if got := scalarC.snapshot(); len(got) != 2 {
		t.Fatalf("legacy scalar (firehose) received %v, want 2 events", got)
	}
	if got := filteredC.snapshot(); len(got) != 1 || got[0] != string(audit.EventLogin) {
		t.Fatalf("filtered subscription received %v, want [login]", got)
	}
}

func TestBuildApp_AuditWebhookEmptyEventTypesIsFirehose(t *testing.T) {
	t.Parallel()
	c, srv := newSubCollector(t)

	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 32
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{
		{Name: "all", URL: srv.URL}, // no event_types -> firehose
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogout})
	if got := c.snapshot(); len(got) != 2 {
		t.Fatalf("empty-filter subscription received %v, want both events (firehose)", got)
	}
}

func TestBuildApp_AuditWebhookRejectsDuplicateName(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{
		{Name: "dup", URL: "https://a.internal/audit"},
		{Name: "dup", URL: "https://b.internal/audit"},
	}
	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("expected error on duplicate subscription name")
	}
}

func TestBuildApp_AuditWebhookRejectsDefaultNameCollision(t *testing.T) {
	t.Parallel()
	// Scalar url reserves the implicit "default" name; an explicit entry
	// reusing it collides at boot.
	cfg := &config.Config{}
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 16
	cfg.Audit.Webhook.Enabled = true
	cfg.Audit.Webhook.URL = "https://scalar.internal/audit"
	cfg.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{
		{Name: "default", URL: "https://other.internal/audit"},
	}
	if _, err := buildApp(cfg, quietLogger()); err == nil {
		t.Fatal("expected error when a subscription reuses the reserved default name")
	}
}

func TestBuildApp_AuditWebhookRejectsMissingNameOrURL(t *testing.T) {
	t.Parallel()
	nameless := &config.Config{}
	nameless.Audit.Enabled = true
	nameless.Audit.MemoryCapacity = 16
	nameless.Audit.Webhook.Enabled = true
	nameless.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{{URL: "https://x.internal/a"}}
	if _, err := buildApp(nameless, quietLogger()); err == nil {
		t.Fatal("expected error on subscription with empty name")
	}

	urlless := &config.Config{}
	urlless.Audit.Enabled = true
	urlless.Audit.MemoryCapacity = 16
	urlless.Audit.Webhook.Enabled = true
	urlless.Audit.Webhook.Subscriptions = []config.AuditWebhookSubscription{{Name: "n"}}
	if _, err := buildApp(urlless, quietLogger()); err == nil {
		t.Fatal("expected error on subscription with empty url")
	}
}

func TestBuildApp_AuditWebhookRequiresURL(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	defer func() { _ = a.registry.Close() }()
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
	t.Parallel()
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
	defer func() { _ = a.registry.Close() }()

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
	t.Parallel()
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
	defer func() { _ = a.registry.Close() }()
	defer func() { _ = a.auditAsyncSink.Close(context.Background()) }()

	a.recorder.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "user-a"})

	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook never received async-dispatched event")
	}
}

func TestBuildApp_AuditWebhookHeaderPropagation(t *testing.T) {
	t.Parallel()
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
	defer func() { _ = a.registry.Close() }()

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
