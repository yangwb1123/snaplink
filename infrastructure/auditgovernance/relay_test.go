package auditgovernance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type relayClientFunc func(context.Context, *commerce.OutboxEvent) (Receipt, error)

func (f relayClientFunc) Publish(ctx context.Context, event *commerce.OutboxEvent) (Receipt, error) {
	return f(ctx, event)
}

type failureCall struct {
	reason      string
	nextAttempt time.Time
	maxAttempts int
}

type relayStore struct {
	events      []*commerce.OutboxEvent
	completed   []string
	quarantined []string
	failures    []failureCall
}

func (s *relayStore) ClaimOutbox(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	events := s.events
	if len(events) > limit {
		events = events[:limit]
	}
	for _, event := range events {
		event.Status, event.LeaseOwner, event.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
		event.Attempts++
	}
	return events, nil
}

func (s *relayStore) CompleteOutbox(
	_ context.Context, id, _ string, _ time.Time,
) error {
	s.completed = append(s.completed, id)
	return nil
}

func (s *relayStore) FailOutbox(
	_ context.Context, _, _, reason string, _, nextAttempt time.Time, maxAttempts int,
) error {
	s.failures = append(s.failures, failureCall{reason: reason, nextAttempt: nextAttempt, maxAttempts: maxAttempts})
	return nil
}

func (s *relayStore) QuarantineOutbox(
	_ context.Context, id, _, _ string, _ time.Time,
) error {
	s.quarantined = append(s.quarantined, id)
	return nil
}

func (*relayStore) ListDeadOutbox(context.Context, int) ([]*commerce.OutboxEvent, error) {
	return nil, nil
}

func (*relayStore) ReplayOutbox(context.Context, string, time.Time) error { return nil }

func relayEvent(id string) *commerce.OutboxEvent {
	event := validCommerceEvent()
	event.ID = id
	event.Attempts = 0
	return event
}

func TestRelayClassifiesGovernanceResponses(t *testing.T) {
	tests := []struct {
		name        string
		deliveryErr error
		result      RunResult
		reason      string
	}{
		{name: "delivered", result: RunResult{Claimed: 1, Delivered: 1}},
		{name: "redirect quarantined", deliveryErr: &HTTPStatusError{StatusCode: 307}, result: RunResult{Claimed: 1, Quarantined: 1}},
		{name: "conflict quarantined", deliveryErr: &HTTPStatusError{StatusCode: 409}, result: RunResult{Claimed: 1, Quarantined: 1}},
		{name: "bad request dead", deliveryErr: &HTTPStatusError{StatusCode: 400}, result: RunResult{Claimed: 1, Dead: 1}, reason: reasonRejected},
		{name: "unprocessable dead", deliveryErr: &HTTPStatusError{StatusCode: 422}, result: RunResult{Claimed: 1, Dead: 1}, reason: reasonRejected},
		{name: "rate limited retry", deliveryErr: &HTTPStatusError{StatusCode: 429}, result: RunResult{Claimed: 1, Retried: 1}, reason: reasonRateLimited},
		{name: "server retry", deliveryErr: &HTTPStatusError{StatusCode: 503}, result: RunResult{Claimed: 1, Retried: 1}, reason: reasonUnavailable},
		{name: "network retry", deliveryErr: errors.New("dial failed"), result: RunResult{Claimed: 1, Retried: 1}, reason: reasonTransport},
		{name: "protocol conflict quarantined", deliveryErr: ErrProtocolConflict, result: RunResult{Claimed: 1, Quarantined: 1}},
		{name: "invalid receipt quarantined", deliveryErr: ErrInvalidReceipt, result: RunResult{Claimed: 1, Quarantined: 1}},
		{name: "invalid event dead", deliveryErr: ErrInvalidEvent, result: RunResult{Claimed: 1, Dead: 1}, reason: reasonInvalidEvent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &relayStore{events: []*commerce.OutboxEvent{relayEvent("evt-1")}}
			client := relayClientFunc(func(context.Context, *commerce.OutboxEvent) (Receipt, error) {
				return Receipt{EventID: "evt-1"}, test.deliveryErr
			})
			relay := newTestRelay(t, store, client)
			result, err := relay.RunOnce(context.Background())
			if err != nil || result != test.result {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			assertRelayTransition(t, store, test.result, test.reason)
		})
	}
}

func TestRelayAuthorizationPausePreservesMemoryOutboxFact(t *testing.T) {
	store := commerce.NewMemoryStore()
	service, err := commerce.NewService(store, commerce.WithIDGenerator(func(prefix string) (string, error) {
		return prefix + "-1", nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-a", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 100, IdempotencyKey: "topup-1", OccurredAt: clientTestNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	client := relayClientFunc(func(context.Context, *commerce.OutboxEvent) (Receipt, error) {
		return Receipt{}, &HTTPStatusError{StatusCode: 403}
	})
	relay := newTestRelay(t, store, client)
	result, err := relay.RunOnce(context.Background())
	if !errors.Is(err, ErrAuthorizationRejected) || result.Retried != 1 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	dead, err := store.ListDeadOutbox(context.Background(), 10)
	if err != nil || len(dead) != 0 {
		t.Fatalf("authorization failure entered dead letter: %+v err=%v", dead, err)
	}
	assertDeferredFactCanBeReclaimed(t, store)
}

func assertDeferredFactCanBeReclaimed(t *testing.T, store commerce.OutboxStore) {
	t.Helper()
	before, err := store.ClaimOutbox(context.Background(), "relay-2", clientTestNow, time.Second, 10)
	if err != nil || len(before) != 0 {
		t.Fatalf("fact was not delayed: %+v err=%v", before, err)
	}
	after, err := store.ClaimOutbox(
		context.Background(), "relay-2", clientTestNow.Add(2*time.Second), time.Second, 10,
	)
	if err != nil || len(after) != 1 || after[0].Status != commerce.OutboxLeased {
		t.Fatalf("fact was not preserved for retry: %+v err=%v", after, err)
	}
}

func TestRelayAuthorizationFailureDefersFactAndPausesBatch(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprintf("status_%d", status), func(t *testing.T) {
			store := &relayStore{events: []*commerce.OutboxEvent{relayEvent("evt-1"), relayEvent("evt-2")}}
			var calls int
			client := relayClientFunc(func(context.Context, *commerce.OutboxEvent) (Receipt, error) {
				calls++
				return Receipt{}, &HTTPStatusError{StatusCode: status}
			})
			result, err := newTestRelay(t, store, client).RunOnce(context.Background())
			if !errors.Is(err, ErrAuthorizationRejected) || result.Retried != 1 || calls != 1 {
				t.Fatalf("result=%+v calls=%d err=%v", result, calls, err)
			}
			if len(store.failures) != 1 || store.failures[0].reason != reasonAuthorization ||
				store.failures[0].maxAttempts != 0 || !store.failures[0].nextAttempt.After(clientTestNow) {
				t.Fatalf("unexpected failure transition: %+v", store.failures)
			}
		})
	}
}

func TestRelayPersistsOnlySanitizedFailureReason(t *testing.T) {
	store := &relayStore{events: []*commerce.OutboxEvent{relayEvent("evt-1")}}
	client := relayClientFunc(func(context.Context, *commerce.OutboxEvent) (Receipt, error) {
		return Receipt{}, fmt.Errorf("network rejected client_secret=%s", "top-secret")
	})
	if _, err := newTestRelay(t, store, client).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.failures) != 1 || strings.Contains(store.failures[0].reason, "top-secret") {
		t.Fatalf("unsafe failure reason: %+v", store.failures)
	}
	if store.failures[0].reason != reasonTransport {
		t.Fatalf("reason = %q", store.failures[0].reason)
	}
}

func TestRelayBackoffIsExponentialJitteredAndCapped(t *testing.T) {
	store := &relayStore{}
	relay := newTestRelay(t, store, relayClientFunc(nil))
	tests := []struct {
		attempts int
		minimum  time.Duration
		maximum  time.Duration
	}{
		{attempts: 1, minimum: 750 * time.Millisecond, maximum: time.Second},
		{attempts: 2, minimum: 1500 * time.Millisecond, maximum: 2 * time.Second},
		{attempts: 20, minimum: 6 * time.Second, maximum: 8 * time.Second},
	}
	for _, test := range tests {
		delay := relay.backoff(&commerce.OutboxEvent{ID: "evt-1", Attempts: test.attempts})
		if delay < test.minimum || delay > test.maximum {
			t.Errorf("attempt %d delay=%v, want [%v,%v]", test.attempts, delay, test.minimum, test.maximum)
		}
	}
}

func newTestRelay(t *testing.T, store commerce.OutboxStore, client Client) *Relay {
	t.Helper()
	relay, err := NewRelay(store, client, RelayConfig{
		Owner: "relay-1", InitialBackoff: time.Second, MaxBackoff: 8 * time.Second,
	}, WithRelayClock(func() time.Time { return clientTestNow }))
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

func assertRelayTransition(t *testing.T, store *relayStore, result RunResult, reason string) {
	t.Helper()
	if result.Delivered == 1 && len(store.completed) != 1 {
		t.Fatal("delivery was not completed")
	}
	if result.Quarantined == 1 && len(store.quarantined) != 1 {
		t.Fatal("delivery was not quarantined")
	}
	if result.Dead+result.Retried == 1 {
		if len(store.failures) != 1 || store.failures[0].reason != reason {
			t.Fatalf("unexpected failure transition: %+v", store.failures)
		}
		if result.Dead == 1 && store.failures[0].maxAttempts != 1 {
			t.Fatalf("dead max attempts = %d", store.failures[0].maxAttempts)
		}
		if result.Retried == 1 && store.failures[0].maxAttempts != 10 {
			t.Fatalf("retry max attempts = %d", store.failures[0].maxAttempts)
		}
	}
}

var _ commerce.OutboxStore = (*relayStore)(nil)
