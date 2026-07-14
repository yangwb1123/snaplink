package clienttrust_test

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

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/clienttrust"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/shared/core"
)

func newStoreWithClient(t *testing.T, clientID string) core.ClientStore {
	t.Helper()
	store := defaultimpl.NewMemoryClientStore()
	if err := store.Add(context.Background(), &core.Client{ID: clientID, Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	return store
}

func TestUpdateAndAlert_PersistsScoreOntoClient(t *testing.T) {
	t.Parallel()
	store := newStoreWithClient(t, "client-1")
	activity := clienttrust.NewMemoryClientActivityStore()
	scorer := &clienttrust.ClientTrustScorer{Activity: activity}
	now := time.Now()

	got, err := clienttrust.UpdateAndAlert(context.Background(), store, scorer, nil, "client-1", 0, now)
	if err != nil {
		t.Fatalf("UpdateAndAlert: %v", err)
	}
	if got.Value != clienttrust.ColdStartScore {
		t.Errorf("returned score = %v, want cold-start default", got.Value)
	}

	persisted, err := store.Get(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if persisted.ClientTrustScore != clienttrust.ColdStartScore {
		t.Errorf("persisted ClientTrustScore = %v, want %v", persisted.ClientTrustScore, clienttrust.ColdStartScore)
	}
	if !persisted.ClientTrustSetAt.Equal(now) {
		t.Errorf("persisted ClientTrustSetAt = %v, want %v", persisted.ClientTrustSetAt, now)
	}
}

func TestUpdateAndAlert_UnknownClientErrors(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	scorer := &clienttrust.ClientTrustScorer{Activity: clienttrust.NewMemoryClientActivityStore()}
	_, err := clienttrust.UpdateAndAlert(context.Background(), store, scorer, nil, "ghost", 0.5, time.Now())
	if err != core.ErrNoSuchClient {
		t.Fatalf("err = %v, want core.ErrNoSuchClient", err)
	}
}

// TestUpdateAndAlert_EdgeTriggeredThresholdCross drives four consecutive
// recomputes through the same client and asserts the alert fires exactly on
// the two genuine downward crossings — not on every recompute that happens
// to be below threshold, and not on the recovery itself.
func TestUpdateAndAlert_EdgeTriggeredThresholdCross(t *testing.T) {
	t.Parallel()
	const clientID = "client-edge"
	// 0.45 sits BELOW the cold-start default (0.5) and the post-rotation
	// score (0.7) but ABOVE the post-scope-anomaly score (0.4) computed
	// below, so only step 3 crosses it.
	const threshold = 0.45
	store := newStoreWithClient(t, clientID)
	activity := clienttrust.NewMemoryClientActivityStore()
	scorer := &clienttrust.ClientTrustScorer{Activity: activity}

	sink := audit.NewMemorySink(64)
	rec := audit.New(sink)
	now := time.Now()

	// 1) First-ever score: no activity yet -> cold-start default (0.5),
	// at/above threshold: no alert.
	if _, err := clienttrust.UpdateAndAlert(context.Background(), store, scorer, rec, clientID, threshold, now); err != nil {
		t.Fatalf("UpdateAndAlert #1: %v", err)
	}
	assertAlertCount(t, sink, 0)

	// 2) Rotation burst pushes the score to 0.7 (1 - 0.3), still >= threshold: no alert.
	for i := 0; i < clienttrust.DefaultRotationFrequencyThreshold; i++ {
		mustRecord(t, activity, clientID, clienttrust.ClientActivitySecretRotation, now)
	}
	if _, err := clienttrust.UpdateAndAlert(context.Background(), store, scorer, rec, clientID, threshold, now.Add(time.Minute)); err != nil {
		t.Fatalf("UpdateAndAlert #2: %v", err)
	}
	assertAlertCount(t, sink, 0)

	// 3) Scope anomaly on top pushes the combined penalty to 0.6 -> score 0.4,
	// crossing BELOW threshold for the first time: one alert.
	mustRecord(t, activity, clientID, clienttrust.ClientActivityScopeAnomaly, now)
	if _, err := clienttrust.UpdateAndAlert(context.Background(), store, scorer, rec, clientID, threshold, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("UpdateAndAlert #3: %v", err)
	}
	assertAlertCount(t, sink, 1)

	// 4) Re-scoring with the SAME still-below-threshold activity must NOT
	// fire a second alert (edge-triggered, not level-triggered).
	if _, err := clienttrust.UpdateAndAlert(context.Background(), store, scorer, rec, clientID, threshold, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("UpdateAndAlert #4: %v", err)
	}
	assertAlertCount(t, sink, 1)
}

func assertAlertCount(t *testing.T, sink *audit.MemorySink, want int) {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{Type: clienttrust.EventClientTrustThresholdCrossed})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != want {
		t.Fatalf("alert count = %d, want %d", len(events), want)
	}
}

// TestUpdateAndAlert_FiresWebhookOnThresholdCross proves the "reuse the
// existing webhook engine, build no new alerting mechanism" design end to
// end: a real platform/lifecycle/webhook.Engine tapping a real
// *audit.Recorder delivers a signed POST to a real httptest server the
// instant UpdateAndAlert crosses the configured threshold.
func TestUpdateAndAlert_FiresWebhookOnThresholdCross(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var received []audit.Event
	var hit atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Store(true)
		body, _ := io.ReadAll(r.Body)
		var e audit.Event
		_ = json.Unmarshal(body, &e)
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx := context.Background()
	subs := webhook.NewMemorySubscriptionStore()
	if _, err := subs.Create(ctx, webhook.EventSubscription{
		URL:        srv.URL,
		EventTypes: []audit.EventType{clienttrust.EventClientTrustThresholdCrossed},
		Secret:     "s3cr3t",
	}); err != nil {
		t.Fatalf("Create subscription: %v", err)
	}
	eng := webhook.NewEngine(subs, webhook.NewMemoryDeadLetterStore(0), webhook.WithHTTPClient(srv.Client()))
	defer func() { _ = eng.Close(context.Background()) }()

	rec := audit.New(audit.NewMemorySink(16))
	rec.AddSink(eng)

	const clientID = "client-webhook"
	store := newStoreWithClient(t, clientID)
	activity := clienttrust.NewMemoryClientActivityStore()
	now := time.Now()
	for i := 0; i < 6; i++ {
		mustRecord(t, activity, clientID, clienttrust.ClientActivityAuthFailure, now)
	}
	for i := 0; i < 2; i++ {
		mustRecord(t, activity, clientID, clienttrust.ClientActivityAuthSuccess, now)
	}
	scorer := &clienttrust.ClientTrustScorer{Activity: activity}

	// 75% failure rate -> score 0.6, below the 0.8 threshold: a first-ever
	// score already below threshold is level-triggered (see crossedBelow).
	if _, err := clienttrust.UpdateAndAlert(ctx, store, scorer, rec, clientID, 0.8, now); err != nil {
		t.Fatalf("UpdateAndAlert: %v", err)
	}

	waitForCondition(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 1
	})
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected exactly 1 webhook delivery, got %d", len(received))
	}
	if received[0].ClientID != clientID {
		t.Errorf("delivered event ClientID = %q, want %q", received[0].ClientID, clientID)
	}
	if received[0].Type != clienttrust.EventClientTrustThresholdCrossed {
		t.Errorf("delivered event Type = %q, want %q", received[0].Type, clienttrust.EventClientTrustThresholdCrossed)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
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
