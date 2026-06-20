package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
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
	s := newCIBAStoreForTest(t)
	ctx := context.Background()
	for _, r := range []*oauth.CIBARequest{nil, {ClientID: "c"}, {SubjectID: "u"}} {
		if _, err := s.Issue(ctx, r); !errors.Is(err, oauth.ErrCIBARequestInvalid) {
			t.Fatalf("want ErrCIBARequestInvalid, got %v", err)
		}
	}
}

func TestCIBAStore_MissingAndExpiredCollapse(t *testing.T) {
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
