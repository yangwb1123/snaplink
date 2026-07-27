package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/protocols/oauth"
)

func newCIBAStoreForTest(t *testing.T) *CIBAStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "ciba.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	s, err := NewCIBAStore(dsn)
	if err != nil {
		t.Fatalf("NewCIBAStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func sampleCIBAReq() *oauth.CIBARequest {
	now := time.Now().UTC()
	return &oauth.CIBARequest{
		ClientID:       "client-a",
		SubjectID:      "alice",
		Provider:       "ciba",
		Scopes:         []string{"openid", "profile"},
		ACRValues:      "urn:acr:strong",
		BindingMessage: "approve 1234",
		Resources:      []string{"https://api.example"},
		Nonce:          "n-1",
		Interval:       5 * time.Second,
		CreatedAt:      now,
		ExpiresAt:      now.Add(2 * time.Minute),
	}
}

func TestCIBAStore_IssueGetRoundTrip(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	id, err := s.Issue(ctx, sampleCIBAReq())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SubjectID != "alice" || got.ClientID != "client-a" || got.Status != oauth.CIBAPending {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if len(got.Scopes) != 2 || got.BindingMessage != "approve 1234" || got.Interval != 5*time.Second {
		t.Fatalf("field mismatch: %+v", got)
	}
}

func TestCIBAStore_IssueRejectsInvalid(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	for _, r := range []*oauth.CIBARequest{nil, {ClientID: "c"}, {SubjectID: "u"}} {
		if _, err := s.Issue(ctx, r); !errors.Is(err, oauth.ErrCIBARequestInvalid) {
			t.Fatalf("want ErrCIBARequestInvalid, got %v", err)
		}
	}
}

func TestCIBAStore_MissingAndExpiredCollapse(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	r := sampleCIBAReq()
	r.ExpiresAt = time.Now().Add(-time.Second)
	id, _ := s.Issue(ctx, r)
	if _, err := s.Get(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("expired: %v", err)
	}
}

func TestCIBAStore_SetStatusLifecycle(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	id, _ := s.Issue(ctx, sampleCIBAReq())
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBADenied); !errors.Is(err, oauth.ErrCIBARequestResolved) {
		t.Fatalf("want ErrCIBARequestResolved, got %v", err)
	}
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
}

func TestCIBAStore_UpdateLastPollAndPrune(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	id, _ := s.Issue(ctx, sampleCIBAReq())
	now := time.Now()
	if err := s.UpdateLastPoll(ctx, id, now); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	got, _ := s.Get(ctx, id)
	if got.LastPoll.IsZero() {
		t.Fatal("LastPoll not recorded")
	}
	// expired entry pruned
	r := sampleCIBAReq()
	r.ExpiresAt = time.Now().Add(-time.Hour)
	_, _ = s.Issue(ctx, r)
	n, err := s.PruneExpired(ctx)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least 1 pruned, got %d", n)
	}
}

// TestCIBAStore_ConsumeIfApproved verifies the atomic single-use claim: only an
// approved row is deleted+returned; pending survives; a second consume is
// not-found. The DELETE ... WHERE status='approved' RETURNING is what makes one
// out-of-band approval mint exactly one token set.
func TestCIBAStore_ConsumeIfApproved(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()

	// Pending: not consumed; survives for the next poll.
	idPending, _ := s.Issue(ctx, sampleCIBAReq())
	if _, err := s.ConsumeIfApproved(ctx, idPending); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("pending should be not-found, got %v", err)
	}
	if _, err := s.Get(ctx, idPending); err != nil {
		t.Fatalf("pending request must survive a failed ConsumeIfApproved: %v", err)
	}

	// Approved: consumed once with resources intact; second consume not-found.
	id, _ := s.Issue(ctx, sampleCIBAReq())
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := s.ConsumeIfApproved(ctx, id)
	if err != nil {
		t.Fatalf("consume approved: %v", err)
	}
	if got.SubjectID != "alice" || got.Status != oauth.CIBAApproved {
		t.Fatalf("consumed record wrong: %+v", got)
	}
	if len(got.Resources) != 1 || got.Resources[0] != "https://api.example" {
		t.Fatalf("RFC 8707 Resources dropped/altered: %v", got.Resources)
	}
	if _, err := s.ConsumeIfApproved(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("second consume must be not-found (single-use), got %v", err)
	}
}

// TestCIBAStore_ConsumeIfApprovedSingleWinner asserts that of N concurrent polls
// of one approved request exactly one wins — one approval can never mint N token
// sets even under concurrent token-endpoint polls.
func TestCIBAStore_ConsumeIfApprovedSingleWinner(t *testing.T) {
	t.Parallel()
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	id, _ := s.Issue(ctx, sampleCIBAReq())
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("approve: %v", err)
	}
	const n = 8
	wins := make(chan bool, n)
	for range n {
		go func() {
			_, err := s.ConsumeIfApproved(ctx, id)
			wins <- err == nil
		}()
	}
	won := 0
	for range n {
		if <-wins {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("exactly one concurrent ConsumeIfApproved should win, got %d", won)
	}
}
