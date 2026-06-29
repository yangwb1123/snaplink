package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

// DeleteAllForClient removes every token bound to the client across all
// subjects, wipes the family ledger so a later replay reads as plain
// not-found (not a reuse event), leaves other clients untouched, and treats
// an empty clientID as a no-op rather than a wildcard.
func TestMemoryRefreshTokenStore_DeleteAllForClient(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRefreshTokenStore()
	ctx := context.Background()
	mk := func(tok, user, client string) {
		if err := s.Issue(ctx, tok, &oauth.RefreshToken{
			UserID: user, ClientID: client, FamilyID: "fam-" + tok,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("issue %s: %v", tok, err)
		}
	}
	mk("a1", "u1", "client-a")
	mk("a2", "u2", "client-a") // different subject, same client
	mk("b1", "u1", "client-b")

	n, err := s.DeleteAllForClient(ctx, "client-a")
	if err != nil {
		t.Fatalf("DeleteAllForClient: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}

	// Purged token + its family marker are both gone, so a replay is a
	// vanilla not-found rather than a stale reuse-detection signal.
	if _, err := s.Consume(ctx, "a1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("a1 after purge: got %v, want ErrRefreshTokenNotFound", err)
	}
	// A different client's token survives.
	if _, err := s.Inspect(ctx, "b1"); err != nil {
		t.Fatalf("b1 should survive the client-a purge: %v", err)
	}

	// Idempotent: a second purge finds nothing.
	if again, _ := s.DeleteAllForClient(ctx, "client-a"); again != 0 {
		t.Fatalf("second purge deleted %d, want 0", again)
	}
	// Empty clientID is NOT a wildcard.
	if blank, _ := s.DeleteAllForClient(ctx, ""); blank != 0 {
		t.Fatalf("empty clientID deleted %d, want 0", blank)
	}
}
