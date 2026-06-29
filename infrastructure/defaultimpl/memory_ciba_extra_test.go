package defaultimpl_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

func TestMemoryCIBAStore_UpdateLastPoll(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryCIBAStore()
	id, err := s.Issue(ctx, sampleCIBA())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	stamp := time.Now().Add(time.Second).UTC().Truncate(time.Second)
	if err := s.UpdateLastPoll(ctx, id, stamp); err != nil {
		t.Fatalf("UpdateLastPoll: %v", err)
	}
	got, _ := s.Get(ctx, id)
	if !got.LastPoll.Equal(stamp) {
		t.Errorf("LastPoll = %v, want %v", got.LastPoll, stamp)
	}

	// UpdateLastPoll on an unknown id is a silent no-op (slow_down bookkeeping
	// must never fail the poll).
	if err := s.UpdateLastPoll(ctx, "unknown", stamp); err != nil {
		t.Errorf("UpdateLastPoll(unknown) = %v, want nil", err)
	}
}

// TestMemoryCIBAStore_ConsumeIfApproved verifies the single-use claim: only an
// approved request is consumed, and consuming it is destructive + repeatable
// once. Pending requests survive a failed consume (poll keeps working).
func TestMemoryCIBAStore_ConsumeIfApproved(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryCIBAStore()

	// Pending: ConsumeIfApproved must NOT consume it; it survives for the poll.
	idPending, _ := s.Issue(ctx, sampleCIBA())
	if _, err := s.ConsumeIfApproved(ctx, idPending); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("pending should be not-found, got %v", err)
	}
	if _, err := s.Get(ctx, idPending); err != nil {
		t.Fatalf("pending request must survive a failed ConsumeIfApproved: %v", err)
	}

	// Approved: consumed exactly once; the second consume is single-use not-found.
	id, _ := s.Issue(ctx, sampleCIBA())
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
	// RFC 8707 audience must survive Issue->Approve->Consume (no widening).
	if len(got.Resources) != 1 || got.Resources[0] != "https://api.example" {
		t.Fatalf("Resources dropped/altered: %v", got.Resources)
	}
	if _, err := s.ConsumeIfApproved(ctx, id); !errors.Is(err, oauth.ErrCIBARequestNotFound) {
		t.Fatalf("second consume must be not-found (single-use), got %v", err)
	}
}

// TestMemoryCIBAStore_ConsumeIfApprovedAtomicRace asserts that N concurrent
// polls of one approved request yield exactly one winner — the invariant that
// stops one out-of-band approval from minting N token sets.
func TestMemoryCIBAStore_ConsumeIfApprovedAtomicRace(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryCIBAStore()
	id, _ := s.Issue(ctx, sampleCIBA())
	if err := s.SetStatus(ctx, id, oauth.CIBAApproved); err != nil {
		t.Fatalf("approve: %v", err)
	}
	const n = 16
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

func TestGenerateCIBAAuthReqID(t *testing.T) {
	a, err := defaultimpl.GenerateCIBAAuthReqID()
	if err != nil {
		t.Fatalf("GenerateCIBAAuthReqID: %v", err)
	}
	if !strings.HasPrefix(a, oauth.AuthReqIDPrefix) {
		t.Errorf("auth_req_id %q missing prefix %q", a, oauth.AuthReqIDPrefix)
	}
	b, _ := defaultimpl.GenerateCIBAAuthReqID()
	if a == b {
		t.Errorf("two auth_req_ids collided: %q", a)
	}
}
