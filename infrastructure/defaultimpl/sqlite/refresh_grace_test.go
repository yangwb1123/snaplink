package sqlite_test

import (
	"database/sql"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
)

// TestSQLiteRefreshGraceStore_RememberThenLookupReplays proves Lookup is
// idempotently replayable within the grace window — the SAME contract the
// Redis peer's TestRedisRefreshGraceStore_RememberThenLookupReplays enforces.
// A multi-tab SPA or a mobile client's flaky-network retry storm can present
// the SAME just-rotated-away refresh token MORE than twice inside one grace
// window; every one of those presentations must replay the identical cached
// successor. A single-use DELETE-on-read would let only the FIRST such
// presentation hit the cache — every subsequent one would miss and fall
// through to family-reuse detection, killing the very family the grace
// window exists to protect (a self-inflicted logout storm).
func TestSQLiteRefreshGraceStore_RememberThenLookupReplays(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+t.Name()+".db?mode=memory&cache=shared&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := sqlite.NewRefreshGraceStore(db, time.Minute, -1)
	if err != nil {
		t.Fatalf("NewRefreshGraceStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()

	resp := map[string]any{"access_token": "AT", "refresh_token": "RT2", "token_type": "Bearer"}
	s.Remember("consumed-token", resp, now)

	got, ok := s.Lookup("consumed-token", now)
	if !ok {
		t.Fatal("expected grace hit after Remember")
	}
	if got["access_token"] != "AT" || got["refresh_token"] != "RT2" {
		t.Fatalf("successor mismatch: %v", got)
	}
	// Idempotent: a second (and third) double-submit within the window must
	// still replay — this is the exact case a single-use DELETE ... RETURNING
	// Lookup broke: only the first presentation would hit, every later one
	// would miss and trip a false family-reuse kill.
	if _, ok := s.Lookup("consumed-token", now); !ok {
		t.Fatal("expected second within-window lookup to also replay")
	}
	if _, ok := s.Lookup("consumed-token", now); !ok {
		t.Fatal("expected third within-window lookup to also replay")
	}

	// Post-window MUST fail closed so the caller proceeds to family-reuse
	// detection — BCP 4.13 preserved.
	if _, ok := s.Lookup("consumed-token", now.Add(2*time.Minute)); ok {
		t.Fatal("expected miss after the grace window (fail-closed)")
	}
}

func TestSQLiteRefreshGraceStore_UnrememberedTokenMisses(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+t.Name()+".db?mode=memory&cache=shared&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := sqlite.NewRefreshGraceStore(db, time.Minute, -1)
	if err != nil {
		t.Fatalf("NewRefreshGraceStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, ok := s.Lookup("never-rotated", time.Now()); ok {
		t.Fatal("a token never remembered must miss (no replay -> reuse path)")
	}
}
