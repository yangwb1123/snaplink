package webhook_test

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

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/shared/security"
)

// waitFor polls cond until it's true or the deadline elapses, failing the
// test on timeout. Delivery runs in a background goroutine (Record never
// blocks the caller), so tests observe its effect asynchronously.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met before timeout")
	}
}

func TestEngine_Record_NoSubscriptions_NoOutboundTraffic(t *testing.T) {
	t.Parallel()
	var hit atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	dlq := webhook.NewMemoryDeadLetterStore(0)
	eng := webhook.NewEngine(subs, dlq)

	if err := eng.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// Give any (incorrectly-spawned) goroutine a moment to fire before
	// asserting silence.
	time.Sleep(20 * time.Millisecond)
	if hit.Load() {
		t.Error("zero subscriptions must produce zero outbound traffic")
	}
}

func TestEngine_Record_NilEngine_IsSafeNoOp(t *testing.T) {
	t.Parallel()
	var eng *webhook.Engine
	if err := eng.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record on nil engine: %v", err)
	}
}

func TestEngine_Record_DeliversOnlyToMatchingEnabledSubscription(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var received []audit.Event
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var e audit.Event
		_ = json.Unmarshal(body, &e)
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	matching, err := subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Create matching: %v", err)
	}
	_, err = subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogout}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Create non-matching: %v", err)
	}
	_, err = subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t", Disabled: true,
	})
	if err != nil {
		t.Fatalf("Create disabled: %v", err)
	}

	dlq := webhook.NewMemoryDeadLetterStore(0)
	eng := webhook.NewEngine(subs, dlq, webhook.WithHTTPClient(srv.Client()))
	defer func() { _ = eng.Close(context.Background()) }()

	if err := eng.Record(ctx, &audit.Event{Type: audit.EventLogin, ActorID: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 1
	})
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected exactly 1 delivery (the matching enabled subscription), got %d", len(received))
	}
	if received[0].ActorID != "alice" {
		t.Errorf("delivered event mismatch: %+v", received[0])
	}
	_ = matching
}

func TestEngine_Record_SignsPayloadPerSubscriptionSecret(t *testing.T) {
	t.Parallel()
	const secret = "whsec-test"
	var mu sync.Mutex
	var sig string
	var body []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		sig = r.Header.Get(security.WebhookSignatureHeader)
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	_, err := subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: secret,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	eng := webhook.NewEngine(subs, webhook.NewMemoryDeadLetterStore(0), webhook.WithHTTPClient(srv.Client()))
	defer func() { _ = eng.Close(context.Background()) }()

	if err := eng.Record(ctx, &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sig != ""
	})
	mu.Lock()
	gotSig, gotBody := sig, body
	mu.Unlock()
	if err := security.VerifyWebhookSignature([]byte(secret), gotSig, gotBody, time.Now(), security.DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("VerifyWebhookSignature: %v", err)
	}
	if err := security.VerifyWebhookSignature([]byte("wrong-secret"), gotSig, gotBody, time.Now(), security.DefaultWebhookSignatureTolerance); err == nil {
		t.Fatal("verification with the wrong secret must fail")
	}
}

func TestEngine_Record_ExhaustedRetriesDeadLetter(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	sub, err := subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dlq := webhook.NewMemoryDeadLetterStore(0)
	var failedMetric atomic.Int32
	var deadLetteredMetric atomic.Int32
	eng := webhook.NewEngine(subs, dlq,
		webhook.WithHTTPClient(srv.Client()),
		webhook.WithDeliveryRetry(2, time.Millisecond, 5*time.Millisecond),
		webhook.WithMetric(func(outcome string) {
			switch outcome {
			case webhook.OutcomeFailed:
				failedMetric.Add(1)
			case webhook.OutcomeDeadLettered:
				deadLetteredMetric.Add(1)
			}
		}),
	)
	defer func() { _ = eng.Close(context.Background()) }()

	if err := eng.Record(ctx, &audit.Event{Type: audit.EventLogin, ActorID: "bob"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var entries []webhook.DeadLetterEntry
	waitFor(t, 2*time.Second, func() bool {
		var lerr error
		entries, lerr = dlq.List(ctx, webhook.DeadLetterFilter{SubscriptionID: sub.ID})
		return lerr == nil && len(entries) == 1
	})
	if len(entries) != 1 {
		t.Fatalf("expected 1 dead-lettered entry, got %d", len(entries))
	}
	if entries[0].Event.ActorID != "bob" {
		t.Errorf("dead-letter entry event mismatch: %+v", entries[0])
	}
	if failedMetric.Load() != 1 || deadLetteredMetric.Load() != 1 {
		t.Errorf("metric counts: failed=%d deadLettered=%d, want 1 and 1", failedMetric.Load(), deadLetteredMetric.Load())
	}
}

func TestEngine_Replay_SuccessRemovesFromDeadLetterQueue(t *testing.T) {
	t.Parallel()
	var failNext atomic.Bool
	failNext.Store(true)
	var mu sync.Mutex
	var received []audit.Event
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failNext.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var e audit.Event
		_ = json.Unmarshal(body, &e)
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	sub, err := subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dlq := webhook.NewMemoryDeadLetterStore(0)
	eng := webhook.NewEngine(subs, dlq, webhook.WithHTTPClient(srv.Client()), webhook.WithDeliveryRetry(1, time.Millisecond, time.Millisecond))
	defer func() { _ = eng.Close(context.Background()) }()

	if err := eng.Record(ctx, &audit.Event{Type: audit.EventLogin, ActorID: "carol"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var entries []webhook.DeadLetterEntry
	waitFor(t, time.Second, func() bool {
		entries, _ = dlq.List(ctx, webhook.DeadLetterFilter{SubscriptionID: sub.ID})
		return len(entries) == 1
	})

	// Flip the server to succeed, then replay — resolving the subscription
	// FRESH and attempting one more delivery.
	failNext.Store(false)
	replayed, err := eng.Replay(ctx, entries[0].ID)
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if replayed.Event.ActorID != "carol" {
		t.Errorf("replayed entry event mismatch: %+v", replayed)
	}
	if _, err := dlq.Get(ctx, entries[0].ID); err == nil {
		t.Error("a successful replay must remove the entry from the dead-letter queue")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 || received[0].ActorID != "carol" {
		t.Errorf("server did not observe the replayed delivery: %+v", received)
	}
}

func TestEngine_Replay_RepeatFailureUpdatesEntryInPlace(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	sub, err := subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	dlq := webhook.NewMemoryDeadLetterStore(0)
	eng := webhook.NewEngine(subs, dlq, webhook.WithHTTPClient(srv.Client()), webhook.WithDeliveryRetry(1, time.Millisecond, time.Millisecond))
	defer func() { _ = eng.Close(context.Background()) }()

	if err := eng.Record(ctx, &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	var entries []webhook.DeadLetterEntry
	waitFor(t, time.Second, func() bool {
		entries, _ = dlq.List(ctx, webhook.DeadLetterFilter{SubscriptionID: sub.ID})
		return len(entries) == 1
	})
	id := entries[0].ID

	if _, err := eng.Replay(ctx, id); err == nil {
		t.Fatal("expected replay against a still-failing endpoint to error")
	}
	got, err := dlq.Get(ctx, id)
	if err != nil {
		t.Fatalf("entry must remain queued after a repeat failure: %v", err)
	}
	if got.Attempts < 2 {
		t.Errorf("Attempts = %d, want >= 2 (original + replay)", got.Attempts)
	}
	if got.LastError == "" {
		t.Error("expected LastError to be updated")
	}
}

func TestEngine_Replay_UnknownEntry(t *testing.T) {
	t.Parallel()
	eng := webhook.NewEngine(webhook.NewMemorySubscriptionStore(), webhook.NewMemoryDeadLetterStore(0))
	if _, err := eng.Replay(context.Background(), "nope"); err == nil {
		t.Fatal("expected error replaying an unknown dead-letter id")
	}
}

// TestEngine_Close_AbortsInFlightDeliveryPromptly proves the documented
// Close contract: cancelling the Engine's delivery context aborts an
// in-flight POST immediately rather than waiting out the handler (which,
// in this test, never responds at all). Without that cancellation, Close
// would hang until its own ctx deadline — a shutdown-path regression this
// test would catch.
func TestEngine_Close_AbortsInFlightDeliveryPromptly(t *testing.T) {
	t.Parallel()
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block // deliberately never released within the test lifetime
	}))
	defer func() {
		close(block)
		srv.Close()
	}()

	subs := webhook.NewMemorySubscriptionStore()
	ctx := context.Background()
	if _, err := subs.Create(ctx, webhook.EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "s3cr3t",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	eng := webhook.NewEngine(subs, webhook.NewMemoryDeadLetterStore(0),
		webhook.WithHTTPClient(srv.Client()),
		webhook.WithDeliveryRetry(1, time.Millisecond, time.Millisecond),
	)
	if err := eng.Record(ctx, &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// Give the delivery goroutine a moment to actually issue the HTTP
	// request before closing, so Close races a REAL in-flight POST rather
	// than winning by never having started one.
	time.Sleep(20 * time.Millisecond)

	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := eng.Close(closeCtx); err != nil {
		t.Fatalf("Close did not return promptly (handler never responds, so a hang here means "+
			"cancellation isn't aborting the in-flight POST): %v", err)
	}
}
