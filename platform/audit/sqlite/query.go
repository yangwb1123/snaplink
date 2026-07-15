package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

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
    metadata_json, prev_hash, hash, server_version`

// rowScanner abstracts both *sql.Row and *sql.Rows so Get + Query
// share scanEvent.
type rowScanner interface {
	Scan(dest ...any) error
}

// scannedRow holds the nullable-string columns of one row before they're
// copied onto an audit.Event — split out of scanEvent (rather than local
// variables there) purely to keep that function under the per-function
// line budget; applyTo is the copy step.
type scannedRow struct {
	reqID, traceID, spanID, parentSpanID sql.NullString
	actorID, actorIP, ua                 sql.NullString
	clientID, tenantID, prov, strat      sql.NullString
	sessID, tokID, reason                sql.NullString
	prev, hash, serverVersion            sql.NullString
}

// applyTo copies row's scanned columns onto e. Every audit.Event field
// added to selectColumns/insertEvent needs a line here too — see
// scanEvent's doc for what happens when one is missed.
func (row scannedRow) applyTo(e *audit.Event) {
	e.RequestID = row.reqID.String
	e.TraceID = row.traceID.String
	e.SpanID = row.spanID.String
	e.ParentSpanID = row.parentSpanID.String
	e.ActorID = row.actorID.String
	e.ActorIP = row.actorIP.String
	e.UserAgent = row.ua.String
	e.ClientID = row.clientID.String
	e.TenantID = row.tenantID.String
	e.Provider = row.prov.String
	e.TokenStrategy = row.strat.String
	e.SessionID = row.sessID.String
	e.TokenID = row.tokID.String
	e.Reason = row.reason.String
	e.PrevHash = row.prev.String
	e.Hash = row.hash.String
	e.ServerVersion = row.serverVersion.String
}

func scanEvent(r rowScanner) (*audit.Event, error) {
	var (
		typ, outcome string
		tsNS         int64
		metaJSON     sql.NullString
		e            = &audit.Event{}
		row          scannedRow
	)
	if err := r.Scan(
		&e.ID, &typ, &outcome, &tsNS,
		&row.reqID, &row.traceID, &row.spanID, &row.parentSpanID,
		&row.actorID, &row.actorIP, &row.ua,
		&row.clientID, &row.tenantID, &row.prov, &row.strat,
		&row.sessID, &row.tokID, &row.reason,
		&metaJSON, &row.prev, &row.hash, &row.serverVersion,
	); err != nil {
		return nil, err
	}
	e.Type = audit.EventType(typ)
	e.Outcome = audit.Outcome(outcome)
	e.Timestamp = time.Unix(0, tsNS).UTC()
	row.applyTo(e)
	if metaJSON.String != "" {
		e.Metadata = map[string]string{}
		if err := json.Unmarshal([]byte(metaJSON.String), &e.Metadata); err != nil {
			return nil, fmt.Errorf("audit/sqlite: unmarshal metadata: %w", err)
		}
	}
	return e, nil
}
