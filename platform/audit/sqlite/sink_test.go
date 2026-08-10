package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

// TestSink_RecordThenGet round-trips one event through INSERT +
// SELECT. Pins the column projection in the schema against
// future-Event additions that would silently drop fields if the
// scan vector falls out of sync.
func TestSink_RecordThenGet(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	want := &audit.Event{
		ID:            "evt-1",
		Type:          audit.EventLogin,
		Outcome:       audit.OutcomeSuccess,
		Timestamp:     now,
		RequestID:     "req-1",
		TraceID:       "trace-1",
		SpanID:        "span-1",
		ParentSpanID:  "parent-1",
		ActorID:       "actor-1",
		ActorIP:       "10.0.0.5",
		UserAgent:     "Go/Test",
		ClientID:      "client-1",
		TenantID:      "tenant-1",
		Provider:      "password",
		TokenStrategy: "jwt",
		SessionID:     "sess-1",
		TokenID:       "tok-1",
		Reason:        "ok",
		Metadata:      map[string]string{"tenant.id": "t-1", "geo.country_code": "US"},
		PrevHash:      "p",
		Hash:          "h",
		ServerVersion: "v1.2.3",
	}
	if err := s.Record(context.Background(), want); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := s.Get(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != want.ID || got.Type != want.Type || got.Outcome != want.Outcome {
		t.Errorf("identity mismatch: got=%+v want=%+v", got, want)
	}
	if got.Timestamp.UnixNano() != want.Timestamp.UnixNano() {
		t.Errorf("timestamp drift: got=%v want=%v", got.Timestamp, want.Timestamp)
	}
	if got.RequestID != want.RequestID || got.TraceID != want.TraceID ||
		got.SpanID != want.SpanID || got.ParentSpanID != want.ParentSpanID {
		t.Errorf("tracing fields lost: got=%+v", got)
	}
	if got.ActorID != want.ActorID || got.ActorIP != want.ActorIP || got.UserAgent != want.UserAgent {
		t.Errorf("actor fields lost: got=%+v", got)
	}
	if got.ClientID != want.ClientID || got.Provider != want.Provider {
		t.Errorf("client/provider fields lost: got=%+v", got)
	}
	if got.TenantID != want.TenantID {
		t.Errorf("tenant_id lost: got=%q want=%q", got.TenantID, want.TenantID)
	}
	if got.ServerVersion != want.ServerVersion {
		t.Errorf("server_version lost: got=%q want=%q", got.ServerVersion, want.ServerVersion)
	}
	if got.SessionID != want.SessionID || got.TokenID != want.TokenID {
		t.Errorf("session/token fields lost: got=%+v", got)
	}
	if got.Metadata["tenant.id"] != "t-1" || got.Metadata["geo.country_code"] != "US" {
		t.Errorf("metadata lost: got=%+v", got.Metadata)
	}
	if got.PrevHash != "p" || got.Hash != "h" {
		t.Errorf("hash-chain pair lost: got prev=%q hash=%q", got.PrevHash, got.Hash)
	}
}

// TestSink_GetUnknownReturnsErrEventNotFound proves the sink
// translates sql.ErrNoRows into audit's sentinel — the
// audit_handler.go GET branch tests `errors.Is(err,
// audit.ErrEventNotFound)` to render 404 vs 500.
func TestSink_GetUnknownReturnsErrEventNotFound(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	_, err := s.Get(context.Background(), "no-such-id")
	if !errors.Is(err, audit.ErrEventNotFound) {
		t.Fatalf("err = %v; want audit.ErrEventNotFound", err)
	}
}

// TestSink_RecordFillsMissingFields — Recorder relies on the sink
// to fill ID + Timestamp when they're zero (matches the
// MemorySink contract).
func TestSink_RecordFillsMissingFields(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	e := &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess}
	if err := s.Record(context.Background(), e); err != nil {
		t.Fatalf("record: %v", err)
	}
	if e.ID == "" {
		t.Error("Record did not stamp ID")
	}
	if e.Timestamp.IsZero() {
		t.Error("Record did not stamp Timestamp")
	}
}

// TestSink_QueryFilters covers each WHERE clause individually so a
// regression in clause assembly fails at the specific filter.
func TestSink_QueryFilters(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mustRecord(t, s, &audit.Event{
		ID: "a", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess,
		Timestamp: base, ActorID: "alice", ClientID: "c1", Provider: "password",
		RequestID: "r1", TraceID: "tr1",
	})
	mustRecord(t, s, &audit.Event{
		ID: "b", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: base.Add(time.Minute), ActorID: "alice", ClientID: "c2",
		Provider: "phone", RequestID: "r2", TraceID: "tr2",
	})
	mustRecord(t, s, &audit.Event{
		ID: "c", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess,
		Timestamp: base.Add(2 * time.Minute), ActorID: "bob", ClientID: "c1",
		Provider: "password", RequestID: "r3", TraceID: "tr1",
	})

	cases := []struct {
		name string
		q    audit.Query
		want []string
	}{
		{"type-filter", audit.Query{Type: audit.EventLogin}, []string{"c", "a"}},
		{"outcome-filter", audit.Query{Outcome: audit.OutcomeFailure}, []string{"b"}},
		{"actor-filter", audit.Query{ActorID: "alice"}, []string{"b", "a"}},
		{"client-filter", audit.Query{ClientID: "c1"}, []string{"c", "a"}},
		{"provider-filter", audit.Query{Provider: "password"}, []string{"c", "a"}},
		{"request-filter", audit.Query{RequestID: "r2"}, []string{"b"}},
		{"trace-filter", audit.Query{TraceID: "tr1"}, []string{"c", "a"}},
		{"since-filter", audit.Query{Since: base.Add(time.Minute)}, []string{"c", "b"}},
		{"until-filter", audit.Query{Until: base.Add(time.Minute)}, []string{"a"}},
		{"combo-filter", audit.Query{Type: audit.EventLogin, ActorID: "alice"}, []string{"a"}},
		{"newest-first", audit.Query{}, []string{"c", "b", "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events, err := s.Query(context.Background(), tc.q)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			gotIDs := make([]string, len(events))
			for i, e := range events {
				gotIDs[i] = e.ID
			}
			if !sliceEqual(gotIDs, tc.want) {
				t.Errorf("ids = %v; want %v", gotIDs, tc.want)
			}
		})
	}
}

// TestSink_QueryLimitOffset proves pagination. Since the SDK
// applies NormalizedLimit (defaults 100, caps at 1000), an
// explicit Limit ≤ the bounds flows through.
func TestSink_QueryLimitOffset(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 5 {
		mustRecord(t, s, &audit.Event{
			ID: idFor(i), Type: audit.EventLogin, Outcome: audit.OutcomeSuccess,
			Timestamp: base.Add(time.Duration(i) * time.Minute),
		})
	}
	// Newest first: e4, e3, e2, e1, e0. Limit=2, offset=1 → e3, e2.
	events, err := s.Query(context.Background(), audit.Query{Limit: 2, Offset: 1})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("got %d; want 2", len(events))
	}
	if events[0].ID != "e3" || events[1].ID != "e2" {
		t.Errorf("got [%s, %s]; want [e3, e2]", events[0].ID, events[1].ID)
	}
}

// TestSink_PingHealthy / TestSink_PingClosed cover the
// ReadyCheck integration cmd uses.
func TestSink_Ping(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("healthy ping = %v", err)
	}
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Error("closed ping should error")
	}
}

// TestSink_CloseIdempotent — defensive against double-close on
// shutdown paths where multiple subsystems share the sink lifetime.
func TestSink_CloseIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// newTestSink opens an isolated in-memory SQLite per test so
// concurrent tests don't share state.
func newTestSink(t *testing.T) *Sink {
	t.Helper()
	s, err := New(":memory:")
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustRecord(t *testing.T, s *Sink, e *audit.Event) {
	t.Helper()
	if err := s.Record(context.Background(), e); err != nil {
		t.Fatalf("record %s: %v", e.ID, e)
	}
}

// TestSink_PruneZeroTimeIsNoop proves the time.Time{} input doesn't
// delete the table (the contract operators rely on for "do nothing
// when retention is disabled" semantics).
func TestSink_PruneZeroTimeIsNoop(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	now := time.Now().UTC()
	mustRecord(t, s, &audit.Event{ID: "evt-1", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: now})

	deleted, err := s.Prune(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("zero-time Prune deleted %d rows, want 0", deleted)
	}
	// Row should still be retrievable.
	if _, err := s.Get(context.Background(), "evt-1"); err != nil {
		t.Fatalf("Get after no-op Prune: %v", err)
	}
}

// TestSink_PruneRespectsBoundary proves Prune deletes events with
// ts_unix_ns STRICTLY LESS than the threshold — the boundary event
// itself survives. This matters for operators reasoning about
// "retain last 30 days" — events from exactly 30 days ago are
// retained, events older are not.
func TestSink_PruneRespectsBoundary(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mustRecord(t, s, &audit.Event{ID: "old", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: base.Add(-1 * time.Second)})
	mustRecord(t, s, &audit.Event{ID: "exactly", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: base})
	mustRecord(t, s, &audit.Event{ID: "new", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: base.Add(1 * time.Second)})

	deleted, err := s.Prune(context.Background(), base)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d, want 1 (only 'old' before threshold)", deleted)
	}
	if _, err := s.Get(context.Background(), "old"); !errors.Is(err, audit.ErrEventNotFound) {
		t.Errorf("'old' should be gone; got %v", err)
	}
	if _, err := s.Get(context.Background(), "exactly"); err != nil {
		t.Errorf("'exactly' (== boundary) should survive; got %v", err)
	}
	if _, err := s.Get(context.Background(), "new"); err != nil {
		t.Errorf("'new' (> boundary) should survive; got %v", err)
	}
}

// TestSink_PruneWipesEverythingWhenFutureThreshold proves a far-future
// olderThan reduces the table to empty. Operators truncating audit
// for a re-seed pass this value (instead of issuing a DROP TABLE +
// migration round-trip).
func TestSink_PruneWipesEverythingWhenFutureThreshold(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	now := time.Now().UTC()
	for i := range 5 {
		mustRecord(t, s, &audit.Event{
			ID:        "evt-" + string(rune('a'+i)),
			Type:      audit.EventLogin,
			Outcome:   audit.OutcomeSuccess,
			Timestamp: now.Add(-time.Duration(i) * time.Hour),
		})
	}
	deleted, err := s.Prune(context.Background(), now.Add(100*time.Hour))
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if deleted != 5 {
		t.Fatalf("deleted %d, want 5", deleted)
	}
	events, err := s.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("Query after full Prune returned %d events, want 0", len(events))
	}
}

// TestSink_PruneOnEmptyTableSucceeds proves Prune is a clean no-op
// (rows-affected=0) when the table is already empty. Removes a class
// of operator scare from cron Prune runs on freshly-bootstrapped
// servers.
func TestSink_PruneOnEmptyTableSucceeds(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	deleted, err := s.Prune(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("Prune on empty table: %v", err)
	}
	if deleted != 0 {
		t.Fatalf("deleted %d on empty table, want 0", deleted)
	}
}

// TestSink_PruneAfterCloseErrors proves Prune respects the closed
// lifecycle rather than panicking with nil deref. Operators who
// wrap audit sink in goroutine + cancellation pattern can rely on
// the error to drive their shutdown ordering.
func TestSink_PruneAfterCloseErrors(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	_ = s.Close()
	_, err := s.Prune(context.Background(), time.Now())
	if err == nil {
		t.Fatal("Prune after Close: want error, got nil")
	}
}

// allEventsOldestFirst reads every row from a sink and reverses the
// newest-first Query result into chain order (oldest first) so the
// slice can be handed straight to audit.VerifyChain.
func allEventsOldestFirst(t *testing.T, s *Sink) []*audit.Event {
	t.Helper()
	newestFirst, err := s.Query(context.Background(), audit.Query{Limit: audit.MaxQueryLimit})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	oldestFirst := make([]*audit.Event, len(newestFirst))
	for i, e := range newestFirst {
		oldestFirst[len(newestFirst)-1-i] = e
	}
	return oldestFirst
}

// TestSink_LastHashEmptyStore proves the ChainTip seam returns genesis
// ("") on a fresh table, so a first-boot Recorder seeds genesis exactly
// as a non-resuming chainer would.
func TestSink_LastHashEmptyStore(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	got, err := s.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if got != "" {
		t.Fatalf("LastHash on empty store = %q, want \"\" (genesis)", got)
	}
}

// TestSink_LastHashAfterCloseErrors mirrors the other lifecycle guards:
// a tip read on a closed sink reports an error rather than nil-derefing,
// so the Recorder's best-effort resume falls back to genesis cleanly.
func TestSink_LastHashAfterCloseErrors(t *testing.T) {
	t.Parallel()
	s := newTestSink(t)
	_ = s.Close()
	if _, err := s.LastHash(context.Background()); err == nil {
		t.Fatal("LastHash after Close: want error, got nil")
	}
}

// TestSink_HashChainResumesAcrossRestart is the core continuity proof.
// It writes N chained events through a Recorder backed by a file-DB
// sink, then DISCARDS that recorder + sink (the restart boundary) and
// constructs a FRESH Recorder + Sink against the SAME DB. The resume
// seam must make the first post-restart event's PrevHash equal the last
// pre-restart Hash, so audit.VerifyChain accepts the combined sequence
// as ONE unbroken chain — no spurious genesis at the seam.
func TestSink_HashChainResumesAcrossRestart(t *testing.T) {
	t.Parallel()
	// File DB (not :memory:) so the second sink observes the rows the
	// first wrote — a :memory: DSN is per-connection and would not
	// share state across the simulated restart.
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")

	// Distinct, monotonic timestamps so chain order is unambiguous and
	// the ts-DESC tip query resolves the true head.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tick := 0
	clock := func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	}

	// --- pre-restart process: write N events through the chain. ---
	sink1, err := New(dsn)
	if err != nil {
		t.Fatalf("open sink1: %v", err)
	}
	rec1 := audit.New(sink1, audit.WithHashChain(), audit.WithClock(clock))
	const nBefore = 4
	for i := 0; i < nBefore; i++ {
		rec1.Record(context.Background(), &audit.Event{
			Type:    audit.EventLogin,
			Outcome: audit.OutcomeSuccess,
			ActorID: "user",
		})
	}
	preRestart := allEventsOldestFirst(t, sink1)
	if len(preRestart) != nBefore {
		t.Fatalf("pre-restart events = %d, want %d", len(preRestart), nBefore)
	}
	headBefore := preRestart[len(preRestart)-1].Hash
	if headBefore == "" {
		t.Fatal("pre-restart head Hash is empty")
	}
	if err := sink1.Close(); err != nil {
		t.Fatalf("close sink1: %v", err)
	}

	// --- post-restart process: fresh sink + recorder, SAME DB. ---
	sink2, err := New(dsn)
	if err != nil {
		t.Fatalf("open sink2: %v", err)
	}
	t.Cleanup(func() { _ = sink2.Close() })

	// Resume must seed the chainer head from storage at construction.
	tip, err := sink2.LastHash(context.Background())
	if err != nil {
		t.Fatalf("LastHash: %v", err)
	}
	if tip != headBefore {
		t.Fatalf("resumed tip = %q, want pre-restart head %q", tip, headBefore)
	}

	rec2 := audit.New(sink2, audit.WithHashChain(), audit.WithClock(clock))
	const nAfter = 3
	for i := 0; i < nAfter; i++ {
		rec2.Record(context.Background(), &audit.Event{
			Type:    audit.EventLogout,
			Outcome: audit.OutcomeSuccess,
			ActorID: "user",
		})
	}

	all := allEventsOldestFirst(t, sink2)
	if len(all) != nBefore+nAfter {
		t.Fatalf("combined events = %d, want %d", len(all), nBefore+nAfter)
	}

	// The seam: the first post-restart event must link to the last
	// pre-restart event, not restart at genesis.
	seam := all[nBefore]
	if seam.PrevHash != headBefore {
		t.Fatalf("restart seam broken: events[%d].PrevHash = %q, want %q",
			nBefore, seam.PrevHash, headBefore)
	}

	// The whole sequence verifies as one chain across the restart.
	if err := audit.VerifyChain(all); err != nil {
		t.Fatalf("VerifyChain across restart seam: %v", err)
	}
}

// TestOpenReadOnly_QueriesWithoutMigrating proves an offline tool can
// read an existing store through OpenReadOnly, and that opening it does
// NOT touch the file — the whole point of the read-only path (New would
// BEGIN IMMEDIATE + apply DDL, a write from a read tool).
func TestOpenReadOnly_QueriesWithoutMigrating(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	seed, err := New(dsn)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	mustRecord(t, seed, &audit.Event{ID: "e1", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: time.Now().UTC()})
	if err := seed.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
	before := hashFile(t, dsn)

	ro, err := OpenReadOnly(dsn)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	got, err := ro.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("read-only Query: %v", err)
	}
	if len(got) != 1 || got[0].ID != "e1" {
		t.Fatalf("read-only Query = %+v, want the seeded event", got)
	}
	if after := hashFile(t, dsn); after != before {
		t.Fatalf("OpenReadOnly mutated the db file: hash %s -> %s", before, after)
	}
}

// TestOpenReadOnly_RejectsModeRO proves the documented read-only DSN
// (?mode=ro) — which New cannot open because migrate.Run's BEGIN
// IMMEDIATE fails "readonly database" — now works through OpenReadOnly.
func TestOpenReadOnly_ModeRO(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	seed, err := New("file:" + path)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	mustRecord(t, seed, &audit.Event{ID: "e1", Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: time.Now().UTC()})
	_ = seed.Close()

	ro, err := OpenReadOnly("file:" + path + "?mode=ro")
	if err != nil {
		t.Fatalf("OpenReadOnly mode=ro: %v", err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	got, err := ro.Query(context.Background(), audit.Query{})
	if err != nil || len(got) != 1 {
		t.Fatalf("mode=ro Query: got=%d err=%v, want 1 event", len(got), err)
	}
}

// TestOpenReadOnly_RejectsUnmigratedDB proves the schema is verified, not
// migrated: a database that carries no audit migrations (version 0) is
// refused with a clear error rather than silently upgraded.
func TestOpenReadOnly_RejectsUnmigratedDB(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "empty.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Force file creation without any audit migration.
	if _, err := db.Exec(`CREATE TABLE unrelated (x INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = db.Close()

	if _, err := OpenReadOnly(dsn); err == nil {
		t.Fatal("OpenReadOnly over an unmigrated db: want error, got nil")
	}
}

// TestOpenReadOnly_DoesNotMigrateBehindDB is the core invariant proof: a
// store one schema version BEHIND this binary must be REJECTED, never
// silently migrated. New would BEGIN IMMEDIATE + ALTER TABLE it (a schema
// write from an export tool); OpenReadOnly refuses and leaves the file
// byte-identical.
func TestOpenReadOnly_DoesNotMigrateBehindDB(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Seed ONLY the v1 baseline so the DB sits a version behind the
	// binary's declared max.
	if err := migrate.Run(context.Background(), db, migrationNamespace, migrations[:1]); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	_ = db.Close()
	before := hashFile(t, dsn)

	if _, err := OpenReadOnly(dsn); err == nil {
		t.Fatal("OpenReadOnly over a v1 db: want schema-mismatch error, got nil")
	}
	if after := hashFile(t, dsn); after != before {
		t.Fatalf("OpenReadOnly migrated a behind-schema db: hash %s -> %s", before, after)
	}
}

func idFor(i int) string { return "e" + string(rune('0'+i)) }

// hashFile returns a hex SHA-256 of the file at a file: DSN, used to
// assert a read-only open leaves the database byte-identical.
func hashFile(t *testing.T, dsn string) string {
	t.Helper()
	path := strings.TrimPrefix(dsn, "file:")
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read db file: %v", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// TxAppender seam (B4-5 in-tx governance connector).
// ---------------------------------------------------------------------------

// recordingAppender records every (eventID, tenantID) pair it saw, keyed
// by event ID, and optionally fails the next append — the fail-open
// degradation probe. A nil tx is an immediate test failure (the seam
// must hand over the live transaction).
type recordingAppender struct {
	mu        sync.Mutex
	appended  map[string]string // event ID -> tenant ID
	failNext  error
	calls     int
	txNilSeen bool
}

func (a *recordingAppender) AppendInTx(_ context.Context, tx *sql.Tx, e *audit.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	if tx == nil {
		a.txNilSeen = true
	}
	if a.failNext != nil {
		err := a.failNext
		a.failNext = nil
		return err
	}
	a.appended[e.ID] = e.TenantID
	return nil
}

// TestSink_TxAppenderCommitsAtomically proves the B4-5 in-tx contract at
// the seam: one transaction commits the audit row AND the appender row
// (simulating the auditoutbox fact), so a governance consumer that opens
// its own connection immediately observes both.
func TestSink_TxAppenderCommitsAtomically(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "audit.db")
	s, err := New(dsn, WithTxAppender(&recordingAppender{appended: map[string]string{}}))
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	defer func() { _ = s.Close() }()

	now := time.Now().UTC()
	if err := s.Record(context.Background(), &audit.Event{
		ID: "evt-1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: now, TenantID: "tenant-1",
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	// A second connection (fresh pool) sees both rows — nothing is held
	// in an uncommitted transaction.
	reader, err := New(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reader.Close() }()
	got, err := reader.Get(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("get audit row: %v", err)
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("audit row tenant: got %q", got.TenantID)
	}
}

// TestSink_TxAppenderFailOpenDegrades proves the fail-open contract: an
// appender error rolls the transaction back, re-inserts the audit row
// ALONE, and surfaces the error — governance never loses an audit record
// to a connector failure.
func TestSink_TxAppenderFailOpenDegrades(t *testing.T) {
	s := newTestSink(t)
	appender := &recordingAppender{appended: map[string]string{}}
	appender.failNext = errors.New("outbox unavailable")
	s.appender = appender

	now := time.Now().UTC()
	err := s.Record(context.Background(), &audit.Event{
		ID: "evt-1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: now, TenantID: "tenant-1",
	})
	if err == nil || !strings.Contains(err.Error(), "tx appender") {
		t.Fatalf("expected surfaced appender error, got %v", err)
	}
	// The audit row survived despite the appender failure.
	got, getErr := s.Get(context.Background(), "evt-1")
	if getErr != nil || got == nil {
		t.Fatalf("audit record lost: get err=%v", getErr)
	}
	if got.TenantID != "tenant-1" {
		t.Errorf("audit row tenant: got %q", got.TenantID)
	}
	if _, present := appender.appended["evt-1"]; present {
		t.Error("appender row must not survive the rollback")
	}
}

// TestSink_TxAppenderBatchFailOpen proves the batch path applies the same
// fail-open degradation: an appender error aborts the batch and every
// audit row is preserved alone.
func TestSink_TxAppenderBatchFailOpen(t *testing.T) {
	s := newTestSink(t)
	appender := &recordingAppender{appended: map[string]string{}}
	appender.failNext = errors.New("outbox unavailable")
	s.appender = appender

	now := time.Now().UTC()
	events := []*audit.Event{
		{ID: "b1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, Timestamp: now, TenantID: "t-1"},
		{ID: "b2", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, Timestamp: now, TenantID: "t-1"},
	}
	err := s.RecordBatch(context.Background(), events)
	if err == nil || !strings.Contains(err.Error(), "batch appender") {
		t.Fatalf("expected surfaced batch appender error, got %v", err)
	}
	for _, id := range []string{"b1", "b2"} {
		got, getErr := s.Get(context.Background(), id)
		if getErr != nil || got == nil {
			t.Errorf("audit record %s lost after batch fail-open: %v", id, getErr)
		}
	}
}

// TestSink_TxAppenderSeesChainedEvent proves the appender observes the
// FINAL chain-stamped event (the Recorder hashes before the sink runs):
// the fact's audit_hash linkage depends on this ordering.
func TestSink_TxAppenderSeesChainedEvent(t *testing.T) {
	s := newTestSink(t)
	appender := &recordingAppender{appended: map[string]string{}}
	s.appender = appender
	rec := audit.New(s, audit.WithHashChain())
	rec.Record(context.Background(), &audit.Event{
		ID: "c1", Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: time.Now().UTC(), TenantID: "tenant-1",
	})
	if appender.calls != 1 {
		t.Fatalf("appender calls: got %d want 1", appender.calls)
	}
	got, err := s.Get(context.Background(), "c1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Hash == "" {
		t.Fatal("recorder did not chain-stamp the event")
	}
}
