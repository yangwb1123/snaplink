package memorystoreoauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth/oauthspi"
)

// TestMemoryCIBAPushDeadLetterStore_RecordAndReplay proves Record persists
// the payload NotifyPush would have delivered, and Replay returns a COPY
// (mutating it back must not corrupt the stored entry).
func TestMemoryCIBAPushDeadLetterStore_RecordAndReplay(t *testing.T) {
	t.Parallel()
	s := NewMemoryCIBAPushDeadLetterStore(0)
	ctx := context.Background()
	payload := oauthspi.PushPayload{AuthReqID: "areq-1", AccessToken: "AT", ExpiresIn: 3600}

	if err := s.Record(ctx, "areq-1", payload, errors.New("http 500")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, err := s.Replay(ctx, "areq-1")
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if *got != payload {
		t.Errorf("replayed payload = %+v, want %+v", *got, payload)
	}
	got.AccessToken = "TAMPERED"
	got2, _ := s.Replay(ctx, "areq-1")
	if got2.AccessToken != "AT" {
		t.Fatalf("Replay returned an aliased copy: %v", got2.AccessToken)
	}
}

// TestMemoryCIBAPushDeadLetterStore_EmptyDeliveryIDMintsID proves an empty
// deliveryID (defensive fallback) still records under a synthesized id
// that ListUnacknowledged surfaces.
func TestMemoryCIBAPushDeadLetterStore_EmptyDeliveryIDMintsID(t *testing.T) {
	t.Parallel()
	s := NewMemoryCIBAPushDeadLetterStore(0)
	if err := s.Record(context.Background(), "", oauthspi.PushPayload{}, errors.New("e")); err != nil {
		t.Fatalf("Record: %v", err)
	}
	ids, err := s.ListUnacknowledged(context.Background())
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(ids) != 1 || ids[0] == "" {
		t.Fatalf("expected one minted id, got %v", ids)
	}
}

// TestMemoryCIBAPushDeadLetterStore_AcknowledgeExcludesFromListing proves
// Acknowledge removes an entry from ListUnacknowledged, and Acknowledge /
// Replay on an unknown id both error.
func TestMemoryCIBAPushDeadLetterStore_AcknowledgeExcludesFromListing(t *testing.T) {
	t.Parallel()
	s := NewMemoryCIBAPushDeadLetterStore(0)
	ctx := context.Background()
	_ = s.Record(ctx, "areq-1", oauthspi.PushPayload{}, errors.New("e"))
	_ = s.Record(ctx, "areq-2", oauthspi.PushPayload{}, errors.New("e"))

	if err := s.Acknowledge(ctx, "areq-1"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	ids, _ := s.ListUnacknowledged(ctx)
	if len(ids) != 1 || ids[0] != "areq-2" {
		t.Fatalf("ListUnacknowledged = %v, want [areq-2]", ids)
	}
	if err := s.Acknowledge(ctx, "no-such-id"); err == nil {
		t.Fatal("expected error acknowledging an unknown id")
	}
	if _, err := s.Replay(ctx, "no-such-id"); err == nil {
		t.Fatal("expected error replaying an unknown id")
	}
}

// TestMemoryCIBAPushDeadLetterStore_TTLExpiryHidesFromListing proves a
// positive entryTTL hides (but does not delete) stale entries from
// ListUnacknowledged — mirroring the push-approval store's lazy-expiry
// listing convention.
func TestMemoryCIBAPushDeadLetterStore_TTLExpiryHidesFromListing(t *testing.T) {
	t.Parallel()
	s := NewMemoryCIBAPushDeadLetterStore(10 * time.Millisecond)
	ctx := context.Background()
	_ = s.Record(ctx, "areq-1", oauthspi.PushPayload{}, errors.New("e"))

	time.Sleep(20 * time.Millisecond)
	ids, err := s.ListUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("ListUnacknowledged: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected the expired entry to be hidden, got %v", ids)
	}
	// Still replayable — TTL only bounds listing visibility, not data loss.
	if _, err := s.Replay(ctx, "areq-1"); err != nil {
		t.Fatalf("Replay of a TTL-hidden (but not deleted) entry: %v", err)
	}
}

var _ oauthspi.CIBAPushDeadLetterStore = (*MemoryCIBAPushDeadLetterStore)(nil)
