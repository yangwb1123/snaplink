package bcl

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type testIssuer struct {
	mu     sync.Mutex
	tokens []string
}

func (i *testIssuer) IssueLogoutToken(_ context.Context, _ *Request) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	token := time.Now().String()
	i.tokens = append(i.tokens, token)
	return token, nil
}

type testNotifier struct {
	mu       sync.Mutex
	failures int
	tokens   []string
}

func (n *testNotifier) Notify(_ context.Context, _ string, token string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tokens = append(n.tokens, token)
	if n.failures > 0 {
		n.failures--
		return errors.New("temporary")
	}
	return nil
}

func TestManagerQueuesAndReplaysWithFreshToken(t *testing.T) {
	store := NewMemoryStore(10)
	issuer := &testIssuer{}
	notifier := &testNotifier{}
	mgr := NewManager(issuer, notifier, store, WithRetryInterval(time.Hour))
	t.Cleanup(func() { _ = mgr.Close(context.Background()) })
	failure := Failure{TenantID: "t1", ClientID: "client", Subject: "local", TokenSubject: "pairwise", URI: "https://rp.example/bcl", LastError: "down"}
	if err := mgr.RecordFailure(context.Background(), failure); err != nil {
		t.Fatalf("record: %v", err)
	}
	entries, err := mgr.ListFailures(context.Background(), "t1", 10)
	if err != nil || len(entries) != 1 {
		t.Fatalf("list = %v, %v", entries, err)
	}
	entry, err := mgr.ReplayFailure(context.Background(), entries[0].ID, "t1")
	if err != nil || entry.DeliveredAt.IsZero() {
		t.Fatalf("replay = %+v, %v", entry, err)
	}
	if len(issuer.tokens) != 1 || len(notifier.tokens) != 1 {
		t.Fatalf("tokens issued=%d delivered=%d", len(issuer.tokens), len(notifier.tokens))
	}
	left, _ := mgr.ListFailures(context.Background(), "t1", 10)
	if len(left) != 0 {
		t.Fatalf("delivered failure remains queued: %v", left)
	}
}

func TestManagerReschedulesFailedReplayAndScopesTenant(t *testing.T) {
	store := NewMemoryStore(10)
	issuer := &testIssuer{}
	notifier := &testNotifier{failures: DefaultMaxAttempts}
	mgr := NewManager(issuer, notifier, store, WithRetryInterval(time.Millisecond))
	t.Cleanup(func() { _ = mgr.Close(context.Background()) })
	if err := mgr.RecordFailure(context.Background(), Failure{TenantID: "t1", ClientID: "c", Subject: "s", TokenSubject: "s", URI: "https://rp/bcl"}); err != nil {
		t.Fatal(err)
	}
	entries, _ := mgr.ListFailures(context.Background(), "t1", 10)
	if _, err := mgr.ReplayFailure(context.Background(), entries[0].ID, "t2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant replay = %v", err)
	}
	failed, err := mgr.ReplayFailure(context.Background(), entries[0].ID, "t1")
	if err == nil || failed.Attempts != DefaultMaxAttempts*2 {
		t.Fatalf("failed replay = %+v, %v", failed, err)
	}
	left, _ := mgr.ListFailures(context.Background(), "t1", 10)
	if len(left) != 1 || left[0].LastError == "" {
		t.Fatalf("failure was not rescheduled: %v", left)
	}
}

func TestMemoryStoreLeasePreventsConcurrentReplay(t *testing.T) {
	store := NewMemoryStore(10)
	f, _ := store.Enqueue(context.Background(), Failure{ID: "one", ClientID: "c", FirstFailedAt: time.Now(), NextAttemptAt: time.Now()})
	_, token, err := store.Claim(context.Background(), f.ID, "", time.Minute)
	if err != nil || token == "" {
		t.Fatalf("first claim = %q, %v", token, err)
	}
	if _, _, err := store.Claim(context.Background(), f.ID, "", time.Minute); !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatalf("second claim = %v", err)
	}
	if err := store.Ack(context.Background(), f, "stale"); !errors.Is(err, ErrLeaseUnavailable) {
		t.Fatalf("stale ack = %v", err)
	}
}

func TestManagerBackgroundReplayAndPermanentSuppression(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore(10)
	issuer := &testIssuer{}
	notifier := &testNotifier{}
	mgr := NewManager(issuer, notifier, store, WithRetryInterval(5*time.Millisecond))
	t.Cleanup(func() { _ = mgr.Close(context.Background()) })
	base := Failure{ClientID: "client", Subject: "local", TokenSubject: "local", URI: "https://rp.example/bcl"}
	if err := mgr.RecordFailure(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		left, _ := mgr.ListFailures(context.Background(), "", 10)
		if len(left) == 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	left, _ := mgr.ListFailures(context.Background(), "", 10)
	if len(left) != 0 || notifier.calls() != 1 {
		t.Fatalf("background replay queue=%v calls=%d", left, notifier.calls())
	}
	base.Permanent, base.ClientID = true, "permanent-client"
	if err := mgr.RecordFailure(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	left, _ = mgr.ListFailures(context.Background(), "", 10)
	if len(left) != 1 || notifier.calls() != 1 {
		t.Fatalf("permanent failure was auto-replayed: queue=%v calls=%d", left, notifier.calls())
	}
	if _, err := mgr.ReplayFailure(context.Background(), left[0].ID, ""); err != nil {
		t.Fatalf("manual permanent replay: %v", err)
	}
}

func (n *testNotifier) calls() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.tokens)
}
