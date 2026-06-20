// Package sqlite is a SQLite-backed [audit.Sink] for durable
// multi-replica audit storage.
//
// The MemorySink (default) is a process-local ring buffer — loses
// every event on restart and isn't shared across replicas. The
// SQLite sink replaces it for deployments that want durable audit
// on the same SQLite file the rest of the SDK already uses for
// identity / OAuth / WebAuthn state.
//
// Schema is one table (audit_events) with the queryable fields
// (type, outcome, ts, actor_id, client_id, provider, request_id,
// trace_id) pulled out as columns + indexes so [audit.Query]
// translates into a simple WHERE/ORDER/LIMIT — no per-event scan.
// Metadata, prev_hash, hash, and any future Event fields live in a
// JSON blob the sink unmarshals on Get/Query.
//
// Composes the same way MemorySink does — drop into MultiSink with
// a WebhookSink for fan-out, wrap in AsyncSink to keep the SQLite
// write off the request hot path. Pure-Go via modernc.org/sqlite;
// no CGO required.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/migrate"

	_ "modernc.org/sqlite"
)

// migrations is the ordered schema history for this backend. v1 is the
// baseline (the schema as it shipped before versioned migrations) — an
// already-populated DB no-ops its IF NOT EXISTS statements and is
// stamped v1; a fresh DB has it created. Future column/index changes
// append v2, v3, ... here.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_audit_events", SQL: schema},
	{Version: 2, Name: "add_tenant_id", SQL: migrationV2},
}

// migrationV2 promotes tenant_id to a first-class indexed column so
// per-tenant queries and metering aggregations avoid full-table JSON
// scans. DEFAULT ” ensures existing rows get a consistent non-NULL
// value after the ALTER TABLE.
const migrationV2 = `
ALTER TABLE audit_events ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events(tenant_id);
`

// schema mirrors audit.Event field-by-field for the queryable
// columns; metadata + the hash-chain pair stay in a JSON blob so
// future Event-struct additions don't require a migration.
const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
    id              TEXT    PRIMARY KEY,
    type            TEXT    NOT NULL,
    outcome         TEXT    NOT NULL,
    ts_unix_ns      INTEGER NOT NULL,
    request_id      TEXT,
    trace_id        TEXT,
    span_id         TEXT,
    parent_span_id  TEXT,
    actor_id        TEXT,
    actor_ip        TEXT,
    user_agent      TEXT,
    client_id       TEXT,
    provider        TEXT,
    token_strategy  TEXT,
    session_id      TEXT,
    token_id        TEXT,
    reason          TEXT,
    metadata_json   TEXT,
    prev_hash       TEXT,
    hash            TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_ts        ON audit_events(ts_unix_ns);
CREATE INDEX IF NOT EXISTS idx_audit_events_type      ON audit_events(type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor     ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_client    ON audit_events(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_request   ON audit_events(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_trace     ON audit_events(trace_id);
`

// Sink is the SQLite-backed [audit.Sink].
type Sink struct {
	db *sql.DB
}

// New opens dsn, migrates the schema, and returns the sink.
// Caller owns Close().
//
// Typical production DSN:
//
//	file:/var/lib/sso/audit.db?_journal=WAL&_busy_timeout=5000
//
// Tests / dev: `:memory:` for per-connection isolation;
// `file::memory:?cache=shared` for a shared in-memory pool.
func New(dsn string) (*Sink, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit/sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "audit", migrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit/sqlite: migrate: %w", err)
	}
	return &Sink{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB — shared-pool deployments
// reuse the same connection across SDK subsystems.
func NewWithDB(db *sql.DB) (*Sink, error) {
	if err := migrate.Run(context.Background(), db, "audit", migrations); err != nil {
		return nil, fmt.Errorf("audit/sqlite: migrate: %w", err)
	}
	return &Sink{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *Sink) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *Sink) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *Sink) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("audit/sqlite: closed")
	}
	return s.db.PingContext(ctx)
}

// Record persists e. ID is filled if empty so the audit.Recorder's
// nil-ID guard isn't required.
func (s *Sink) Record(ctx context.Context, e *audit.Event) error {
	if s == nil || s.db == nil {
		return errors.New("audit/sqlite: closed")
	}
	if e == nil {
		return nil
	}
	if e.ID == "" {
		e.ID = newEventID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	return insertEvent(ctx, s.db, e)
}

// insertEvent executes the INSERT for a single event against any execer
// (either a *sql.DB or a *sql.Tx). The caller is responsible for ID and
// Timestamp defaulting before calling this.
type execerContext interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertEvent(ctx context.Context, db execerContext, e *audit.Event) error {
	metaJSON := ""
	if len(e.Metadata) > 0 {
		raw, err := json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("audit/sqlite: marshal metadata: %w", err)
		}
		metaJSON = string(raw)
	}
	_, err := db.ExecContext(ctx, `
        INSERT INTO audit_events (
            id, type, outcome, ts_unix_ns,
            request_id, trace_id, span_id, parent_span_id,
            actor_id, actor_ip, user_agent,
            client_id, tenant_id, provider, token_strategy,
            session_id, token_id, reason,
            metadata_json, prev_hash, hash
        ) VALUES (?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?)`,
		e.ID, string(e.Type), string(e.Outcome), e.Timestamp.UnixNano(),
		e.RequestID, e.TraceID, e.SpanID, e.ParentSpanID,
		e.ActorID, e.ActorIP, e.UserAgent,
		e.ClientID, e.TenantID, e.Provider, e.TokenStrategy,
		e.SessionID, e.TokenID, e.Reason,
		metaJSON, e.PrevHash, e.Hash,
	)
	if err != nil {
		return fmt.Errorf("audit/sqlite: insert: %w", err)
	}
	return nil
}

// RecordBatch persists all events in a single BEGIN IMMEDIATE transaction,
// reducing per-event SQLite overhead by collapsing N INSERTs into one commit.
// Any error aborts the whole batch — the caller must retry.
func (s *Sink) RecordBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	for _, e := range events {
		if e.ID == "" {
			e.ID = newEventID()
		}
		if e.Timestamp.IsZero() {
			e.Timestamp = time.Now()
		}
		if err = insertEvent(ctx, tx, e); err != nil {
			return err
		}
	}
	return tx.Commit()
}
