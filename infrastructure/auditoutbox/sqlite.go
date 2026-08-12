package auditoutbox

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite"
)

// outboxColumns is the audit_outbox column projection, explicitly listed
// (like the audit sink's insertEvent) so a schema change is a deliberate
// migration, never a silent drop.
const outboxColumns = `id, tenant_id, event_type, aggregate_type, aggregate_id,
aggregate_version, idempotency_key, occurred_at_ns, payload, payload_digest,
status, attempts, next_attempt_at_ns, lease_owner, lease_until_ns, last_error,
delivered_at_ns, created_at_ns`

// migrations is the ordered schema history for the audit_outbox table.
// v1 is the baseline; the table lives in the SAME sqlite file as
// audit_events so the fact row can commit in the audit row's
// transaction, but under its own migrate namespace so the audit sink's
// schema checks are unaffected by this connector.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_audit_outbox", SQL: schema},
}

// migrationNamespace is the per-backend key migrate.Run uses for this
// store's schema_migrations_<ns> table.
const migrationNamespace = "auditoutbox"

const schema = `
CREATE TABLE IF NOT EXISTS audit_outbox (
    id                TEXT    PRIMARY KEY,
    tenant_id         TEXT    NOT NULL,
    event_type        TEXT    NOT NULL,
    aggregate_type    TEXT    NOT NULL,
    aggregate_id      TEXT    NOT NULL,
    aggregate_version INTEGER NOT NULL,
    idempotency_key   TEXT    NOT NULL,
    occurred_at_ns    INTEGER NOT NULL,
    payload           TEXT    NOT NULL,
    payload_digest    TEXT    NOT NULL,
    status            TEXT    NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_ns INTEGER NOT NULL DEFAULT 0,
    lease_owner       TEXT    NOT NULL DEFAULT '',
    lease_until_ns    INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT    NOT NULL DEFAULT '',
    delivered_at_ns   INTEGER NOT NULL DEFAULT 0,
    created_at_ns     INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_outbox_key
    ON audit_outbox(tenant_id, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_audit_outbox_status
    ON audit_outbox(status, next_attempt_at_ns);
`

// SQLiteOutboxStore is the durable governance outbox: audit_outbox rows
// in the same sqlite file as the audit chain, written atomically with
// the audit row through [platform/audit/sqlite.WithTxAppender]
// (AppendInTx) and drained by auditgovernance.NewRelay (it implements
// [commerce.OutboxStore]).
type SQLiteOutboxStore struct {
	db *sql.DB
}

// NewSQLiteOutboxStore opens dsn (the SAME dsn the audit sink uses) and
// migrates the audit_outbox schema under its own namespace. Caller owns
// Close().
func NewSQLiteOutboxStore(dsn string) (*SQLiteOutboxStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("auditoutbox/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auditoutbox/sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, migrationNamespace, migrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("auditoutbox/sqlite: migrate: %w", err)
	}
	return &SQLiteOutboxStore{db: db}, nil
}

// NewSQLiteOutboxStoreWithDB wraps an existing *sql.DB — shared-pool
// deployments (the same pool the audit sink wraps) create both tables
// in one connection pool.
func NewSQLiteOutboxStoreWithDB(db *sql.DB) (*SQLiteOutboxStore, error) {
	if err := Migrate(context.Background(), db); err != nil {
		return nil, err
	}
	return &SQLiteOutboxStore{db: db}, nil
}

// Migrate ensures the audit_outbox schema exists on a caller-owned pool.
// Exported for offline tooling (cmd/sso-ctl import) that must create the
// table on the same pool the user store owns WITHOUT constructing a
// SQLiteOutboxStore: its Close() would close that shared *sql.DB.
func Migrate(ctx context.Context, db *sql.DB) error {
	if err := migrate.Run(ctx, db, migrationNamespace, migrations); err != nil {
		return fmt.Errorf("auditoutbox/sqlite: migrate: %w", err)
	}
	return nil
}

// Close releases the connection. Idempotent.
func (s *SQLiteOutboxStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// AppendInTx implements platform/audit/sqlite.TxAppender: it projects
// the audit event through [FactFromAudit] and inserts the fact row into
// the caller's transaction, so the audit row and the outbox fact commit
// atomically (the B4-5 in-tx contract). The class/tenant gates apply
// here too: a non-login-failure event is skipped as a nil op (the audit
// sink only passes events through this hook when the connector owns the
// permitted class), and an unprojectable event fails the transaction —
// the audit sink's fail-open path then preserves the audit row alone.
func (s *SQLiteOutboxStore) AppendInTx(ctx context.Context, tx *sql.Tx, e *audit.Event) error {
	if s == nil || s.db == nil {
		return errors.New("auditoutbox/sqlite: closed")
	}
	fact, err := FactFromAudit(e)
	if err != nil {
		return err
	}
	return InsertEventTx(ctx, tx, fact)
}

// InsertEventTx inserts one outbox row into the caller's transaction.
// It is the generic in-tx append (the login-failure-only FactFromAudit
// gate is NOT applied — callers own the class decision); cmd/sso-ctl
// import uses it to commit the user.import event atomically with the
// user upsert. Idempotent: ON CONFLICT(id) DO NOTHING plus the
// (tenant_id, idempotency_key) unique index make a same-fact re-insert
// a no-op; a conflicting fact is a unique violation surfaced to the
// caller.
func InsertEventTx(ctx context.Context, tx *sql.Tx, fact *commerce.OutboxEvent) error {
	if err := fact.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(fact.Payload)
	if err != nil {
		return fmt.Errorf("auditoutbox/sqlite: encode payload: %w", err)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_outbox (
`+outboxColumns+`
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO NOTHING`,
		fact.ID, fact.TenantID, fact.Type, fact.AggregateType, fact.AggregateID,
		fact.AggregateVersion, fact.IdempotencyKey, timeNano(fact.OccurredAt),
		string(payload), fact.PayloadDigest, fact.Status, fact.Attempts,
		timeNano(fact.NextAttemptAt), fact.LeaseOwner, timeNano(fact.LeaseUntil),
		fact.LastError, timeNano(fact.DeliveredAt), timeNano(fact.CreatedAt))
	if err != nil {
		return fmt.Errorf("auditoutbox/sqlite: insert fact: %w", err)
	}
	return nil
}

// ClaimOutbox implements [commerce.OutboxStore].
func (s *SQLiteOutboxStore) ClaimOutbox(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auditoutbox/sqlite: closed")
	}
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("auditoutbox/sqlite: invalid outbox claim")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT `+outboxColumns+` FROM audit_outbox
WHERE (status='pending' AND next_attempt_at_ns <= ?)
   OR (status='leased' AND lease_until_ns <= ?)
ORDER BY created_at_ns, id LIMIT ?`, timeNano(now), timeNano(now), limit)
	if err != nil {
		return nil, fmt.Errorf("auditoutbox/sqlite: claim: %w", err)
	}
	facts, err := scanFacts(rows)
	if err != nil {
		return nil, err
	}
	for _, fact := range facts {
		_, err = tx.ExecContext(ctx, `UPDATE audit_outbox SET
status='leased', lease_owner=?, lease_until_ns=?, attempts=attempts+1 WHERE id=?`,
			owner, timeNano(now.Add(lease)), fact.ID)
		if err != nil {
			return nil, fmt.Errorf("auditoutbox/sqlite: lease: %w", err)
		}
		fact.Status, fact.LeaseOwner, fact.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
		fact.Attempts++
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return facts, nil
}

// CompleteOutbox implements [commerce.OutboxStore].
func (s *SQLiteOutboxStore) CompleteOutbox(ctx context.Context, id, owner string, deliveredAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE audit_outbox SET
status='delivered', delivered_at_ns=?, lease_owner='', lease_until_ns=0
WHERE id=? AND status='leased' AND lease_owner=?`, timeNano(deliveredAt), id, owner)
	return s.classifyUpdate(ctx, result, err, id, "complete")
}

// FailOutbox implements [commerce.OutboxStore].
func (s *SQLiteOutboxStore) FailOutbox(
	ctx context.Context, id, owner, reason string, _ time.Time, nextAttempt time.Time, maxAttempts int,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE audit_outbox SET
status=CASE WHEN ? > 0 AND attempts >= ? THEN 'dead' ELSE 'pending' END,
next_attempt_at_ns=CASE WHEN ? > 0 AND attempts >= ? THEN next_attempt_at_ns ELSE ? END,
last_error=?, lease_owner='', lease_until_ns=0
WHERE id=? AND status='leased' AND lease_owner=?`,
		maxAttempts, maxAttempts, maxAttempts, maxAttempts, timeNano(nextAttempt),
		boundedError(reason), id, owner)
	return s.classifyUpdate(ctx, result, err, id, "fail")
}

// QuarantineOutbox implements [commerce.OutboxStore].
func (s *SQLiteOutboxStore) QuarantineOutbox(
	ctx context.Context, id, owner, reason string, _ time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE audit_outbox SET
status='quarantined', last_error=?, lease_owner='', lease_until_ns=0
WHERE id=? AND status='leased' AND lease_owner=?`, boundedError(reason), id, owner)
	return s.classifyUpdate(ctx, result, err, id, "quarantine")
}

// ListDeadOutbox implements [commerce.OutboxStore].
func (s *SQLiteOutboxStore) ListDeadOutbox(ctx context.Context, limit int) ([]*commerce.OutboxEvent, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auditoutbox/sqlite: closed")
	}
	query := `SELECT ` + outboxColumns + ` FROM audit_outbox
WHERE status IN ('dead','quarantined') ORDER BY created_at_ns, id`
	args := []any{}
	if limit > 0 {
		query, args = query+` LIMIT ?`, []any{limit}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("auditoutbox/sqlite: list dead: %w", err)
	}
	return scanFacts(rows)
}

// ReplayOutbox implements [commerce.OutboxStore].
func (s *SQLiteOutboxStore) ReplayOutbox(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE audit_outbox SET
status='pending', attempts=0, next_attempt_at_ns=?, last_error='', lease_owner='', lease_until_ns=0
WHERE id=? AND status IN ('dead','quarantined')`, timeNano(now), id)
	return s.classifyUpdate(ctx, result, err, id, "replay")
}

// Pending returns the facts that have not reached a terminal state —
// the durability assertion surface: the connector is proven durable by
// observing pending facts on a FRESH connection BEFORE the relay runs.
func (s *SQLiteOutboxStore) Pending(ctx context.Context) ([]*commerce.OutboxEvent, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("auditoutbox/sqlite: closed")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+outboxColumns+` FROM audit_outbox
WHERE status IN ('pending','leased') ORDER BY created_at_ns, id`)
	if err != nil {
		return nil, fmt.Errorf("auditoutbox/sqlite: pending: %w", err)
	}
	return scanFacts(rows)
}

// classifyUpdate mirrors the commerce postgres store's update
// classification: zero rows updated means either the fact is gone
// (ErrOutboxNotFound) or the lease was lost (ErrOutboxLeaseLost).
func (s *SQLiteOutboxStore) classifyUpdate(
	ctx context.Context, result sql.Result, err error, id, operation string,
) error {
	if err != nil {
		return fmt.Errorf("auditoutbox/sqlite: %s: %w", operation, err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated == 1 {
		return err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM audit_outbox WHERE id=?)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("auditoutbox/sqlite: inspect update: %w", err)
	}
	if !exists {
		return commerce.ErrOutboxNotFound
	}
	return commerce.ErrOutboxLeaseLost
}

func scanFacts(rows *sql.Rows) ([]*commerce.OutboxEvent, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.OutboxEvent, 0)
	for rows.Next() {
		fact := &commerce.OutboxEvent{}
		var occurredAt, nextAttemptAt, leaseUntil, deliveredAt, createdAt int64
		var payload string
		if err := rows.Scan(
			&fact.ID, &fact.TenantID, &fact.Type, &fact.AggregateType, &fact.AggregateID,
			&fact.AggregateVersion, &fact.IdempotencyKey, &occurredAt, &payload, &fact.PayloadDigest,
			&fact.Status, &fact.Attempts, &nextAttemptAt, &fact.LeaseOwner, &leaseUntil,
			&fact.LastError, &deliveredAt, &createdAt,
		); err != nil {
			return nil, fmt.Errorf("auditoutbox/sqlite: scan: %w", err)
		}
		fact.OccurredAt = fromNano(occurredAt)
		fact.NextAttemptAt = fromNano(nextAttemptAt)
		fact.LeaseUntil = fromNano(leaseUntil)
		fact.DeliveredAt = fromNano(deliveredAt)
		fact.CreatedAt = fromNano(createdAt)
		if err := json.Unmarshal([]byte(payload), &fact.Payload); err != nil {
			return nil, fmt.Errorf("auditoutbox/sqlite: decode payload: %w", err)
		}
		result = append(result, fact)
	}
	return result, rows.Err()
}

func fromNano(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

func timeNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixNano()
}
