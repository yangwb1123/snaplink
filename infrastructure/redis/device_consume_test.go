package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func TestDeviceConsumeIfApproved(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	ctx := context.Background()
	mk := func(dc, uc string) {
		if err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: dc, UserCode: uc, ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("issue: %v", err)
		}
	}

	// Pending code: ConsumeIfApproved must NOT consume it (not-found), and the
	// code must survive for the next poll.
	mk("dc-pending", "uc-pending")
	if _, err := s.ConsumeIfApproved(ctx, "dc-pending"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("pending should be not-found, got %v", err)
	}
	if _, err := s.GetByDeviceCode(ctx, "dc-pending"); err != nil {
		t.Fatalf("pending code must survive a failed ConsumeIfApproved: %v", err)
	}

	// Approved code: consumed exactly once, returns the identity.
	mk("dc-ok", "uc-ok")
	if err := s.Approve(ctx, "uc-ok", "user-1", "password", nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := s.ConsumeIfApproved(ctx, "dc-ok")
	if err != nil {
		t.Fatalf("consume approved: %v", err)
	}
	if got.UserID != "user-1" || !got.Approved {
		t.Fatalf("consumed record wrong: %+v", got)
	}
	if _, err := s.ConsumeIfApproved(ctx, "dc-ok"); !errors.Is(err, oauth.ErrDeviceCodeNotFound) {
		t.Fatalf("second consume must be not-found (single-use), got %v", err)
	}
}

func TestDeviceConsumeIfApprovedAtomicRace(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	ctx := context.Background()
	if err := s.Issue(ctx, &oauth.DeviceCode{DeviceCode: "dc-race", UserCode: "uc-race", ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := s.Approve(ctx, "uc-race", "user-1", "password", nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	const n = 16
	wins := make(chan bool, n)
	for range n {
		go func() {
			_, err := s.ConsumeIfApproved(ctx, "dc-race")
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
		t.Fatalf("exactly one concurrent ConsumeIfApproved should win the single-use claim, got %d", won)
	}
}

func TestDeviceConsumeIfApprovedPreservesResources(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewDeviceCodeStore(rdb)
	ctx := context.Background()
	if err := s.Issue(ctx, &oauth.DeviceCode{
		DeviceCode: "dc-res", UserCode: "uc-res", ClientID: "c",
		Resources:  []string{"https://api.example.com"},
		ExpiresAt:  time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := s.Approve(ctx, "uc-res", "user-1", "password", nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got, err := s.ConsumeIfApproved(ctx, "dc-res")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	// RFC 8707 audience restriction must survive Issue->Approve->Consume so the
	// minted token's audience is not widened.
	if len(got.Resources) != 1 || got.Resources[0] != "https://api.example.com" {
		t.Fatalf("Resources dropped/altered: %v", got.Resources)
	}
}
