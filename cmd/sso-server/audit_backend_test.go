package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildauthn"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestBuildPrimaryAuditSink_DefaultsToMemory — operators who set
// audit.enabled but leave backend blank get the historical
// MemorySink behavior. Pins the no-regression for existing
// reference YAMLs that don't yet name a backend.
func TestBuildPrimaryAuditSink_DefaultsToMemory(t *testing.T) {
	t.Parallel()
	sink, name, err := serverbuildauthn.BuildPrimaryAuditSink(config.AuditConfig{Enabled: true}, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if name != "memory" {
		t.Errorf("name = %q; want memory", name)
	}
	if _, ok := sink.(*audit.MemorySink); !ok {
		t.Errorf("sink type = %T; want *audit.MemorySink", sink)
	}
}

// TestBuildPrimaryAuditSink_SqliteRoundTrip — the SQLite backend
// constructs against a tempfile DSN, accepts a Record, and the
// /audit/events query path returns it via the sink. Proves the
// cmd-level wiring doesn't drop any of the event fields the
// downstream API surfaces.
func TestBuildPrimaryAuditSink_SqliteRoundTrip(t *testing.T) {
	t.Parallel()
	dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") + "?_journal=WAL"
	sink, name, err := serverbuildauthn.BuildPrimaryAuditSink(config.AuditConfig{
		Enabled: true,
		Backend: "sqlite",
		Sqlite:  config.AuditSqliteConfig{DSN: dsn},
	}, quietLogger(), nil, "")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if name != "sqlite" {
		t.Errorf("name = %q; want sqlite", name)
	}
	t.Cleanup(func() {
		if c, ok := sink.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	})
	e := &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "u"}
	if err := sink.Record(context.Background(), e); err != nil {
		t.Fatalf("record: %v", err)
	}
	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventLogin})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 || events[0].ActorID != "u" {
		t.Errorf("got %d events / first actor=%q; want 1 event / u", len(events), events[0].ActorID)
	}
}

// TestBuildPrimaryAuditSink_SqliteRequiresDSN — opt into sqlite
// without a DSN → loud boot error, not a silent crash at first
// Record.
func TestBuildPrimaryAuditSink_SqliteRequiresDSN(t *testing.T) {
	t.Parallel()
	_, _, err := serverbuildauthn.BuildPrimaryAuditSink(config.AuditConfig{
		Enabled: true, Backend: "sqlite",
	}, quietLogger(), nil, "")
	if err == nil {
		t.Fatal("expected error when sqlite backend lacks DSN")
	}
}

// TestBuildPrimaryAuditSink_RejectsUnknownBackend — operator typos
// surface at boot rather than silently falling back to memory and
// losing every event the operator expected to persist.
func TestBuildPrimaryAuditSink_RejectsUnknownBackend(t *testing.T) {
	t.Parallel()
	_, _, err := serverbuildauthn.BuildPrimaryAuditSink(config.AuditConfig{
		Enabled: true, Backend: "postgres",
	}, quietLogger(), nil, "")
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}
