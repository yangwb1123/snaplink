package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/migrate"
)

// auditSchema is the Postgres baseline for the audit_events table (the sqlite
// peer's v1 + v2 folded into one fresh baseline). ts_unix_ns is BIGINT (Unix
// nanoseconds, NOT timestamptz — exact round-trip). The hash-chain pair
// (prev_hash, hash) is stored verbatim; the CHAINING itself lives in the
// audit.Recorder, so the sink is a plain append + query store. seq is a
// monotonic insertion-order column replacing SQLite's rowid as the
// same-nanosecond tie-break for LastHash (BIGSERIAL works on Postgres and
// CockroachDB).
const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_events (
    seq             BIGSERIAL,
    id              TEXT    PRIMARY KEY,
    type            TEXT    NOT NULL,
    outcome         TEXT    NOT NULL,
    ts_unix_ns      BIGINT  NOT NULL,
    request_id      TEXT,
    trace_id        TEXT,
    span_id         TEXT,
    parent_span_id  TEXT,
    actor_id        TEXT,
    actor_ip        TEXT,
    user_agent      TEXT,
    client_id       TEXT,
    tenant_id       TEXT    NOT NULL DEFAULT '',
    provider        TEXT,
    token_strategy  TEXT,
    session_id      TEXT,
    token_id        TEXT,
    reason          TEXT,
    metadata_json   TEXT,
    prev_hash       TEXT,
    hash            TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts      ON audit_events(ts_unix_ns);
CREATE INDEX IF NOT EXISTS idx_audit_events_type    ON audit_events(type);
CREATE INDEX IF NOT EXISTS idx_audit_events_actor   ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_client  ON audit_events(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_request ON audit_events(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_trace   ON audit_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant  ON audit_events(tenant_id);
`

var auditMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: auditSchema},
}

// rebind rewrites the SQLite-style '?' placeholders to Postgres '$1','$2',…
// positionally. The audit queries never contain a literal '?' (only
// placeholders), so a straight byte rewrite is safe and keeps the shared
// '?'-based WHERE/INSERT builders dialect-agnostic.
func rebind(query string) string {
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

// AuditSink is the Postgres-backed [audit.Sink] (+ FacetQuerier + BatchSink +
// ChainTip) — durable, queryable, multi-replica audit storage. Drops into a
// MultiSink / AsyncSink exactly like the memory + sqlite peers.
type AuditSink struct {
	db      *sql.DB
	dialect Dialect
}

// NewAuditSink opens cfg.DSN, migrates the schema, and returns the sink.
func NewAuditSink(cfg Config) (*AuditSink, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewAuditSinkWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewAuditSinkWithDB wraps an existing shared *sql.DB (shared-pool deployments).
func NewAuditSinkWithDB(db *sql.DB, dialect Dialect) (*AuditSink, error) {
	if err := Run(context.Background(), db, "audit", auditMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate audit: %w", err)
	}
	return &AuditSink{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent.
func (s *AuditSink) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting. Nil after Close.
func (s *AuditSink) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *AuditSink) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: audit sink closed")
	}
	return s.db.PingContext(ctx)
}

// execContext is the *sql.DB / *sql.Tx subset insertEvent needs so Record and
// RecordBatch share one INSERT path.
type execContext interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const auditInsert = `
    INSERT INTO audit_events (
        id, type, outcome, ts_unix_ns,
        request_id, trace_id, span_id, parent_span_id,
        actor_id, actor_ip, user_agent,
        client_id, tenant_id, provider, token_strategy,
        session_id, token_id, reason,
        metadata_json, prev_hash, hash
    ) VALUES (?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?)`

func insertAuditEvent(ctx context.Context, db execContext, e *audit.Event) error {
	metaJSON := ""
	if len(e.Metadata) > 0 {
		raw, err := json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("postgres: marshal audit metadata: %w", err)
		}
		metaJSON = string(raw)
	}
	_, err := db.ExecContext(ctx, rebind(auditInsert),
		e.ID, string(e.Type), string(e.Outcome), e.Timestamp.UnixNano(),
		e.RequestID, e.TraceID, e.SpanID, e.ParentSpanID,
		e.ActorID, e.ActorIP, e.UserAgent,
		e.ClientID, e.TenantID, e.Provider, e.TokenStrategy,
		e.SessionID, e.TokenID, e.Reason,
		metaJSON, e.PrevHash, e.Hash,
	)
	if err != nil {
		return fmt.Errorf("postgres: audit insert: %w", err)
	}
	return nil
}

// Record persists e, filling ID + Timestamp when empty (matching the sqlite peer).
func (s *AuditSink) Record(ctx context.Context, e *audit.Event) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: audit sink closed")
	}
	if e == nil {
		return nil
	}
	if e.ID == "" {
		e.ID = newAuditEventID()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	return insertAuditEvent(ctx, s.db, e)
}

// RecordBatch persists all events in one transaction (BatchSink). Any error
// aborts the whole batch — the caller retries.
func (s *AuditSink) RecordBatch(ctx context.Context, events []*audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	// Append-only inserts: default isolation is correct (no read-modify-write,
	// so no lost-update risk), but the batch still needs the 40001 retry on a
	// CockroachDB cluster under contention. Re-running is idempotent — each
	// event's ID/Timestamp is stamped once and reused unchanged on a retry.
	return runTx(ctx, s.db, nil, func(tx *sql.Tx) error {
		for _, e := range events {
			if e.ID == "" {
				e.ID = newAuditEventID()
			}
			if e.Timestamp.IsZero() {
				e.Timestamp = time.Now()
			}
			if err := insertAuditEvent(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
}

// Prune deletes events older than olderThan, returning rows removed. Same
// hash-chain caveat as the sqlite peer (pruning leaves the oldest survivor with
// a dangling PrevHash). time.Time{} is a no-op.
func (s *AuditSink) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("postgres: audit sink closed")
	}
	if olderThan.IsZero() {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE ts_unix_ns < $1`, olderThan.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("postgres: audit prune: %w", err)
	}
	return res.RowsAffected()
}

// LastHash returns the most-recent event's Hash so an audit.Recorder with
// WithHashChain() resumes the chain across restarts (ChainTip). "Most recent"
// is ts_unix_ns DESC tie-broken by seq DESC (the monotonic insertion column
// replacing SQLite's rowid). "" on an empty table seeds at genesis.
func (s *AuditSink) LastHash(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("postgres: audit sink closed")
	}
	var hash sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT hash FROM audit_events ORDER BY ts_unix_ns DESC, seq DESC LIMIT 1`,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("postgres: audit last hash: %w", err)
	}
	return hash.String, nil
}

func newAuditEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

var (
	_ audit.Sink         = (*AuditSink)(nil)
	_ audit.FacetQuerier = (*AuditSink)(nil)
	_ audit.BatchSink    = (*AuditSink)(nil)
	_ audit.ChainTip     = (*AuditSink)(nil)
)
