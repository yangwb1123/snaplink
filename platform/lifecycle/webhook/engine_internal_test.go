package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestNewEngine_DefaultClientBlocksRedirects proves NewEngine's own default
// client (no WithHTTPClient override) carries a CheckRedirect that treats
// any 3xx as terminal. Without this, a subscription URL that later 302s
// (compromised or misconfigured receiver, past validateHTTPSURL's shape
// check) would have Go's default http.Client silently follow it -- the same
// SSRF-via-redirect class already closed for CAEP/CIBA push. This is a
// package-internal (white-box) test, unlike this package's other _test.go
// files (package webhook_test), because it needs to read the unexported
// client field directly -- an end-to-end redirect-following proof already
// exists one layer down in auditsink.TestWebhookSink_DoesNotFollowRedirect,
// since newWebhookSink (engine_delivery.go) hands this exact client to
// audit.WebhookSink via WithWebhookHTTPClient for every real delivery.
func TestNewEngine_DefaultClientBlocksRedirects(t *testing.T) {
	e := NewEngine(nil, nil)
	defer func() { _ = e.Close(context.Background()) }()

	if e.client.CheckRedirect == nil {
		t.Fatal("default client has no CheckRedirect: a 3xx subscription response would be silently followed")
	}
	if err := e.client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect(...) = %v, want http.ErrUseLastResponse", err)
	}
}

type failFirstDeleteStore struct {
	DeadLetterStore
	deleteCalls atomic.Int32
}

func (s *failFirstDeleteStore) Delete(ctx context.Context, id string) error {
	if s.deleteCalls.Add(1) == 1 {
		return errors.New("injected cleanup failure")
	}
	return s.DeadLetterStore.Delete(ctx, id)
}

func TestReplayCleanupFailureCannotRedeliver(t *testing.T) {
	var deliveries atomic.Int32
	var replayKey atomic.Value
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		replayKey.Store(r.Header.Get("Idempotency-Key"))
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx := context.Background()
	subs := NewMemorySubscriptionStore()
	sub, err := subs.Create(ctx, EventSubscription{
		URL: srv.URL, EventTypes: []audit.EventType{audit.EventLogin}, Secret: "test-secret",
	})
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	base := NewMemoryDeadLetterStore(10)
	entry, err := base.Add(ctx, DeadLetterEntry{
		SubscriptionID: sub.ID, Event: audit.Event{Type: audit.EventLogin},
	})
	if err != nil {
		t.Fatalf("add dead letter: %v", err)
	}
	dlq := &failFirstDeleteStore{DeadLetterStore: base}
	eng := NewEngine(subs, dlq, WithHTTPClient(srv.Client()))
	defer func() { _ = eng.Close(context.Background()) }()

	first, err := eng.Replay(ctx, entry.ID)
	if !errors.Is(err, ErrReplayCleanup) {
		t.Fatalf("first Replay error = %v, want ErrReplayCleanup", err)
	}
	if first.ReplayState != ReplayStateCleanupPending || deliveries.Load() != 1 {
		t.Fatalf("first replay = %+v, deliveries=%d", first, deliveries.Load())
	}
	if got := replayKey.Load(); got != replayIdempotencyKeyPrefix+entry.ID {
		t.Fatalf("Idempotency-Key = %v", got)
	}

	if _, err := eng.Replay(ctx, entry.ID); err != nil {
		t.Fatalf("cleanup-only replay: %v", err)
	}
	if deliveries.Load() != 1 {
		t.Fatalf("cleanup retry redelivered event: deliveries=%d", deliveries.Load())
	}
	if _, err := base.Get(ctx, entry.ID); !errors.Is(err, ErrDeadLetterNotFound) {
		t.Fatalf("entry remained after cleanup retry: %v", err)
	}
}
