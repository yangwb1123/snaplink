package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/protocols/oauth"

	_ "modernc.org/sqlite"
)

// The SQLite peer of DeleteAllForClient mirrors the memory semantics:
// deletes every row for the client across subjects, wipes the families
// ledger, leaves other clients intact, and no-ops on an empty clientID.
func TestRefreshTokenStore_DeleteAllForClient(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rt.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	s := sqlite.NewRefreshTokenStoreWithDB(db) // runs migration internally
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
	mk("a2", "u2", "client-a")
	mk("b1", "u1", "client-b")

	n, err := s.DeleteAllForClient(ctx, "client-a")
	if err != nil {
		t.Fatalf("DeleteAllForClient: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}
	if _, err := s.Inspect(ctx, "a1"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Fatalf("a1 should be gone: %v", err)
	}
	if _, err := s.Inspect(ctx, "b1"); err != nil {
		t.Fatalf("b1 should survive: %v", err)
	}
	if blank, _ := s.DeleteAllForClient(ctx, ""); blank != 0 {
		t.Fatalf("empty clientID deleted %d, want 0", blank)
	}
}
