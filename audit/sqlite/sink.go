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
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"

	_ "modernc.org/sqlite"
)

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
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit/sqlite: migrate: %w", err)
	}
	return &Sink{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB — shared-pool deployments
// reuse the same connection across SDK subsystems.
func NewWithDB(db *sql.DB) (*Sink, error) {
	if _, err := db.ExecContext(context.Background(), schema); err != nil {
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
	metaJSON := ""
	if len(e.Metadata) > 0 {
		raw, err := json.Marshal(e.Metadata)
		if err != nil {
			return fmt.Errorf("audit/sqlite: marshal metadata: %w", err)
		}
		metaJSON = string(raw)
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO audit_events (
            id, type, outcome, ts_unix_ns,
            request_id, trace_id, span_id, parent_span_id,
            actor_id, actor_ip, user_agent,
            client_id, provider, token_strategy,
            session_id, token_id, reason,
            metadata_json, prev_hash, hash
        ) VALUES (?, ?, ?, ?,  ?, ?, ?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?, ?,  ?, ?, ?)`,
		e.ID, string(e.Type), string(e.Outcome), e.Timestamp.UnixNano(),
		e.RequestID, e.TraceID, e.SpanID, e.ParentSpanID,
		e.ActorID, e.ActorIP, e.UserAgent,
		e.ClientID, e.Provider, e.TokenStrategy,
		e.SessionID, e.TokenID, e.Reason,
		metaJSON, e.PrevHash, e.Hash,
	)
	if err != nil {
		return fmt.Errorf("audit/sqlite: insert: %w", err)
	}
	return nil
}

// Get returns the event with the given id, or [audit.ErrEventNotFound].
func (s *Sink) Get(ctx context.Context, id string) (*audit.Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit/sqlite: closed")
	}
	row := s.db.QueryRowContext(ctx, selectColumns+` FROM audit_events WHERE id = ?`, id)
	e, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, audit.ErrEventNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: get: %w", err)
	}
	return e, nil
}

// Query matches the [audit.Sink] contract. WHERE clauses are
// driven by populated [audit.Query] fields; ORDER BY ts DESC mirrors
// the MemorySink "newest first" guarantee callers expect for
// stable pagination.
func (s *Sink) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit/sqlite: closed")
	}
	var clauses []string
	var args []any
	addEq := func(col, val string) {
		if val == "" {
			return
		}
		clauses = append(clauses, col+" = ?")
		args = append(args, val)
	}
	addEq("type", string(q.Type))
	addEq("outcome", string(q.Outcome))
	addEq("actor_id", q.ActorID)
	addEq("client_id", q.ClientID)
	addEq("provider", q.Provider)
	addEq("request_id", q.RequestID)
	addEq("trace_id", q.TraceID)
	if !q.Since.IsZero() {
		clauses = append(clauses, "ts_unix_ns >= ?")
		args = append(args, q.Since.UnixNano())
	}
	if !q.Until.IsZero() {
		clauses = append(clauses, "ts_unix_ns < ?")
		args = append(args, q.Until.UnixNano())
	}

	sqlStr := selectColumns + ` FROM audit_events`
	if len(clauses) > 0 {
		sqlStr += " WHERE " + strings.Join(clauses, " AND ")
	}
	sqlStr += " ORDER BY ts_unix_ns DESC LIMIT " + strconv.Itoa(q.NormalizedLimit())
	if q.Offset > 0 {
		sqlStr += " OFFSET " + strconv.Itoa(q.Offset)
	}

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: query: %w", err)
	}
	defer rows.Close()
	var out []*audit.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("audit/sqlite: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit/sqlite: rows: %w", err)
	}
	return out, nil
}

// selectColumns names the SELECT projection. Kept in column order
// to keep scanEvent's []any aligned.
const selectColumns = `SELECT
    id, type, outcome, ts_unix_ns,
    request_id, trace_id, span_id, parent_span_id,
    actor_id, actor_ip, user_agent,
    client_id, provider, token_strategy,
    session_id, token_id, reason,
    metadata_json, prev_hash, hash`

// rowScanner abstracts both *sql.Row and *sql.Rows so Get + Query
// share scanEvent.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(r rowScanner) (*audit.Event, error) {
	var (
		typ, outcome              string
		tsNS                      int64
		metaJSON                  sql.NullString
		e                         = &audit.Event{}
		reqID, traceID, spanID    sql.NullString
		parentSpanID              sql.NullString
		actorID, actorIP, ua      sql.NullString
		clientID, prov, strat     sql.NullString
		sessID, tokID, reason     sql.NullString
		prev, hash                sql.NullString
	)
	if err := r.Scan(
		&e.ID, &typ, &outcome, &tsNS,
		&reqID, &traceID, &spanID, &parentSpanID,
		&actorID, &actorIP, &ua,
		&clientID, &prov, &strat,
		&sessID, &tokID, &reason,
		&metaJSON, &prev, &hash,
	); err != nil {
		return nil, err
	}
	e.Type = audit.EventType(typ)
	e.Outcome = audit.Outcome(outcome)
	e.Timestamp = time.Unix(0, tsNS).UTC()
	e.RequestID = reqID.String
	e.TraceID = traceID.String
	e.SpanID = spanID.String
	e.ParentSpanID = parentSpanID.String
	e.ActorID = actorID.String
	e.ActorIP = actorIP.String
	e.UserAgent = ua.String
	e.ClientID = clientID.String
	e.Provider = prov.String
	e.TokenStrategy = strat.String
	e.SessionID = sessID.String
	e.TokenID = tokID.String
	e.Reason = reason.String
	e.PrevHash = prev.String
	e.Hash = hash.String
	if metaJSON.String != "" {
		e.Metadata = map[string]string{}
		if err := json.Unmarshal([]byte(metaJSON.String), &e.Metadata); err != nil {
			return nil, fmt.Errorf("audit/sqlite: unmarshal metadata: %w", err)
		}
	}
	return e, nil
}

// newEventID — same shape as audit.MemorySink uses, kept private
// here so the sink package doesn't depend on an exported helper.
func newEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Compile-time interface assertion.
var _ audit.Sink = (*Sink)(nil)
