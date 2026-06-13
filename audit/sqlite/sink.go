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
	"github.com/snaplink/sso/migrate"

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

// buildWhere translates the populated filter fields of q into a
// "WHERE col = ? AND ..." fragment (empty string when no filters) plus
// the matching positional args. It is the single source of filter
// semantics so Query and Facets WHERE-clause behavior stays identical —
// a divergence would let the facet counts disagree with the rows the
// filter UI then fetches. Limit/Offset are NOT encoded here (they're
// pagination, not filters).
func buildWhere(q audit.Query) (string, []any) {
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
	addEq("tenant_id", q.TenantID)
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
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// Query matches the [audit.Sink] contract. WHERE clauses are
// driven by populated [audit.Query] fields; ORDER BY ts DESC mirrors
// the MemorySink "newest first" guarantee callers expect for
// stable pagination.
func (s *Sink) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit/sqlite: closed")
	}
	where, args := buildWhere(q)

	sqlStr := selectColumns + ` FROM audit_events` + where
	sqlStr += " ORDER BY ts_unix_ns DESC LIMIT " + strconv.Itoa(q.NormalizedLimit())
	if q.Offset > 0 {
		sqlStr += " OFFSET " + strconv.Itoa(q.Offset)
	}

	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, fmt.Errorf("audit/sqlite: query: %w", err)
	}
	defer func() { _ = rows.Close() }()
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

// Facets aggregates per-dimension counts (outcome / type / client /
// provider) over every event matching q's time range + non-dimension
// filters. It reuses buildWhere so the GROUP BY queries honor exactly
// the same filter semantics as Query — the counts describe the same row
// set the filter UI would page through. Limit/Offset are ignored: facets
// summarize the whole filtered window.
//
// One grouped SELECT per dimension keeps each result set bounded by that
// dimension's distinct-value cardinality (small for outcome/type/client/
// provider) rather than scanning + decoding every Event row in Go. The
// total comes from the outcome roll-up so the four queries plus the count
// agree on a single snapshot under SQLite's single-writer model.
// Implements the optional [audit.FacetQuerier] extension.
func (s *Sink) Facets(ctx context.Context, q audit.Query) (*audit.Facets, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("audit/sqlite: closed")
	}
	where, args := buildWhere(q)

	f := &audit.Facets{
		Outcomes:  map[audit.Outcome]int{},
		Types:     map[audit.EventType]int{},
		Clients:   map[string]int{},
		Providers: map[string]int{},
	}

	// Outcome roll-up also yields Total — sum of every matched row.
	if err := s.groupCount(ctx, "outcome", where, args, func(val string, n int) {
		f.Outcomes[audit.Outcome(val)] += n
		f.Total += n
	}); err != nil {
		return nil, err
	}
	if err := s.groupCount(ctx, "type", where, args, func(val string, n int) {
		f.Types[audit.EventType(val)] += n
	}); err != nil {
		return nil, err
	}
	// Empty client_id / provider are skipped: they aren't filter values
	// the UI offers (mirrors the memory backend's Facets.add).
	if err := s.groupCount(ctx, "client_id", where, args, func(val string, n int) {
		if val != "" {
			f.Clients[val] += n
		}
	}); err != nil {
		return nil, err
	}
	if err := s.groupCount(ctx, "provider", where, args, func(val string, n int) {
		if val != "" {
			f.Providers[val] += n
		}
	}); err != nil {
		return nil, err
	}
	return f, nil
}

// groupCount runs `SELECT <col>, COUNT(*) ... GROUP BY <col>` over the
// shared WHERE fragment and feeds each (value, count) pair to visit. col
// is a fixed internal identifier (never user input), so concatenating it
// into the SQL is injection-safe; all variable data rides on args.
func (s *Sink) groupCount(ctx context.Context, col, where string, args []any, visit func(val string, n int)) error {
	sqlStr := "SELECT " + col + ", COUNT(*) FROM audit_events" + where + " GROUP BY " + col
	rows, err := s.db.QueryContext(ctx, sqlStr, args...)
	if err != nil {
		return fmt.Errorf("audit/sqlite: facets %s: %w", col, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var val sql.NullString
		var n int
		if err := rows.Scan(&val, &n); err != nil {
			return fmt.Errorf("audit/sqlite: facets scan %s: %w", col, err)
		}
		visit(val.String, n)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit/sqlite: facets rows %s: %w", col, err)
	}
	return nil
}

// selectColumns names the SELECT projection. Kept in column order
// to keep scanEvent's []any aligned.
const selectColumns = `SELECT
    id, type, outcome, ts_unix_ns,
    request_id, trace_id, span_id, parent_span_id,
    actor_id, actor_ip, user_agent,
    client_id, tenant_id, provider, token_strategy,
    session_id, token_id, reason,
    metadata_json, prev_hash, hash`

// rowScanner abstracts both *sql.Row and *sql.Rows so Get + Query
// share scanEvent.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(r rowScanner) (*audit.Event, error) {
	var (
		typ, outcome                    string
		tsNS                            int64
		metaJSON                        sql.NullString
		e                               = &audit.Event{}
		reqID, traceID, spanID          sql.NullString
		parentSpanID                    sql.NullString
		actorID, actorIP, ua            sql.NullString
		clientID, tenantID, prov, strat sql.NullString
		sessID, tokID, reason           sql.NullString
		prev, hash                      sql.NullString
	)
	if err := r.Scan(
		&e.ID, &typ, &outcome, &tsNS,
		&reqID, &traceID, &spanID, &parentSpanID,
		&actorID, &actorIP, &ua,
		&clientID, &tenantID, &prov, &strat,
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
	e.TenantID = tenantID.String
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

// Prune deletes events with ts_unix_ns < olderThan and returns the
// number of rows removed. Use for audit retention policies — without
// it the table grows monotonically, and after a year of moderate
// traffic the file is large enough to slow Query down even with the
// ts index. Operators typically run this from a cron / systemd
// timer against the same DSN the live server uses (SQLite is
// concurrent-reader / single-writer; Prune blocks new Record calls
// briefly).
//
// Hash-chain caveat: when [audit.WithHashChain] is in use, every
// retained Event's PrevHash points at its predecessor's Hash.
// Pruning the predecessor leaves the FIRST surviving event with
// a dangling PrevHash → [audit.VerifyChain] sees a break at that
// boundary and returns an error. Operators have three options:
//
//  1. Skip Prune entirely (the chain stays whole; the SQLite DB
//     grows; cold-storage offload via Query + delete-by-id outside
//     this helper is the alternative).
//  2. Prune knowing the chain will report a discontinuity at the
//     retention boundary — VerifyChain returns the broken-link
//     error, which operators interpret as "everything after this
//     point is verifiable; everything before was pruned by
//     policy." This is the most common posture for compliance
//     regimes that retain N days of events.
//  3. Pair Prune with re-chaining: dump the surviving events,
//     re-stamp PrevHash on the oldest survivor to point at the
//     [audit.GenesisHash], re-Record. Loses the historical
//     chain-of-custody linkage but produces a clean post-prune
//     state. Not exposed as an API here — operators run a custom
//     migration when they want that posture.
//
// olderThan in the past prunes events older than the timestamp;
// olderThan in the future returns rows-affected=total-row-count
// (the table is wiped). Pass time.Time{} for a no-op (returns 0).
func (s *Sink) Prune(ctx context.Context, olderThan time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("audit/sqlite: closed")
	}
	if olderThan.IsZero() {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_events WHERE ts_unix_ns < ?`, olderThan.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("audit/sqlite: prune: %w", err)
	}
	return res.RowsAffected()
}

// newEventID — same shape as audit.MemorySink uses, kept private
// here so the sink package doesn't depend on an exported helper.
func newEventID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Compile-time interface assertions.
var (
	_ audit.Sink         = (*Sink)(nil)
	_ audit.FacetQuerier = (*Sink)(nil)
	_ audit.BatchSink    = (*Sink)(nil)
)
