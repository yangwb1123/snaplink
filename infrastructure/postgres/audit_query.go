package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// selectAuditColumns names the SELECT projection in column order so
// scanAuditEvent's destinations stay aligned.
const selectAuditColumns = `SELECT
    id, type, outcome, ts_unix_ns,
    request_id, trace_id, span_id, parent_span_id,
    actor_id, actor_ip, user_agent,
    client_id, tenant_id, provider, token_strategy,
    session_id, token_id, reason,
    metadata_json, prev_hash, hash, server_version`

// Get returns the event with id, or [audit.ErrEventNotFound].
func (s *AuditSink) Get(ctx context.Context, id string) (*audit.Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres: audit sink closed")
	}
	row := s.db.QueryRowContext(ctx, selectAuditColumns+` FROM audit_events WHERE id = $1`, id)
	e, err := scanAuditEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, audit.ErrEventNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: audit get: %w", err)
	}
	return e, nil
}

// buildAuditWhere translates q's populated filters into a "WHERE col = ? AND …"
// fragment (in SQLite-style '?' placeholders, rebound to $N at execution) plus
// the matching args. Shared by Query + Facets so their filter semantics stay
// identical. Limit/Offset are pagination, not encoded here.
func buildAuditWhere(q audit.Query) (string, []any) {
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

// Query matches the [audit.Sink] contract: filtered, newest-first, paginated.
func (s *AuditSink) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres: audit sink closed")
	}
	where, args := buildAuditWhere(q)
	sqlStr := selectAuditColumns + ` FROM audit_events` + where
	sqlStr += " ORDER BY ts_unix_ns DESC LIMIT " + strconv.Itoa(q.NormalizedLimit())
	if q.Offset > 0 {
		sqlStr += " OFFSET " + strconv.Itoa(q.Offset)
	}
	rows, err := s.db.QueryContext(ctx, rebind(sqlStr), args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: audit query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*audit.Event
	for rows.Next() {
		e, err := scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: audit scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: audit rows: %w", err)
	}
	return out, nil
}

// Facets aggregates per-dimension counts over q's filtered window (FacetQuerier),
// reusing buildAuditWhere so the counts describe the same rows Query pages.
func (s *AuditSink) Facets(ctx context.Context, q audit.Query) (*audit.Facets, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("postgres: audit sink closed")
	}
	where, args := buildAuditWhere(q)
	f := &audit.Facets{
		Outcomes:  map[audit.Outcome]int{},
		Types:     map[audit.EventType]int{},
		Clients:   map[string]int{},
		Providers: map[string]int{},
	}
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

// groupCount runs `SELECT <col>, COUNT(*) … GROUP BY <col>` over the shared
// WHERE. col is a fixed internal identifier (never user input), so concatenating
// it is injection-safe; variable data rides on args.
func (s *AuditSink) groupCount(ctx context.Context, col, where string, args []any, visit func(val string, n int)) error {
	sqlStr := "SELECT " + col + ", COUNT(*) FROM audit_events" + where + " GROUP BY " + col
	rows, err := s.db.QueryContext(ctx, rebind(sqlStr), args...)
	if err != nil {
		return fmt.Errorf("postgres: audit facets %s: %w", col, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var val sql.NullString
		var n int
		if err := rows.Scan(&val, &n); err != nil {
			return fmt.Errorf("postgres: audit facets scan %s: %w", col, err)
		}
		visit(val.String, n)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: audit facets rows %s: %w", col, err)
	}
	return nil
}

func scanAuditEvent(r scanner) (*audit.Event, error) {
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
		prev, hash, serverVersion       sql.NullString
	)
	if err := r.Scan(
		&e.ID, &typ, &outcome, &tsNS,
		&reqID, &traceID, &spanID, &parentSpanID,
		&actorID, &actorIP, &ua,
		&clientID, &tenantID, &prov, &strat,
		&sessID, &tokID, &reason,
		&metaJSON, &prev, &hash, &serverVersion,
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
	e.ServerVersion = serverVersion.String
	if metaJSON.String != "" {
		e.Metadata = map[string]string{}
		if err := json.Unmarshal([]byte(metaJSON.String), &e.Metadata); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal audit metadata: %w", err)
		}
	}
	return e, nil
}
