package usageledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func insertOutboxEventTx(ctx context.Context, tx *sql.Tx, event *commerce.OutboxEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	payload, err := encodeJSON(event.Payload)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO usage_ledger_outbox (
id, tenant_id, event_type, aggregate_type, aggregate_id, aggregate_version,
idempotency_key, occurred_at_ns, payload, payload_digest, status, attempts,
next_attempt_at_ns, lease_owner, lease_until_ns, last_error, delivered_at_ns, created_at_ns
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,CAST($9 AS JSONB),$10,$11,$12,$13,$14,$15,$16,$17,$18)
ON CONFLICT DO NOTHING`, event.ID, event.TenantID, event.Type, event.AggregateType,
		event.AggregateID, event.AggregateVersion, event.IdempotencyKey, timeNano(event.OccurredAt),
		payload, event.PayloadDigest, event.Status, event.Attempts, timeNano(event.NextAttemptAt),
		event.LeaseOwner, timeNano(event.LeaseUntil), event.LastError, timeNano(event.DeliveredAt),
		timeNano(event.CreatedAt))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: insert outbox: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil || inserted == 1 {
		return err
	}
	return ensureOutboxFactTx(ctx, tx, event)
}

func ensureOutboxFactTx(ctx context.Context, tx *sql.Tx, expected *commerce.OutboxEvent) error {
	byID, err := findOutboxTx(ctx, tx, `id=$1`, expected.ID)
	if err != nil {
		return err
	}
	byKey, err := findOutboxTx(
		ctx, tx, `tenant_id=$1 AND idempotency_key=$2`, expected.TenantID, expected.IdempotencyKey,
	)
	if err != nil {
		return err
	}
	if byID == nil && byKey == nil {
		return commerce.ErrIdempotencyConflict
	}
	if (byID != nil && !sameOutboxFact(byID, expected)) ||
		(byKey != nil && !sameOutboxFact(byKey, expected)) {
		return commerce.ErrIdempotencyConflict
	}
	return nil
}

func findOutboxTx(
	ctx context.Context, tx *sql.Tx, predicate string, args ...any,
) (*commerce.OutboxEvent, error) {
	event, err := scanOutbox(tx.QueryRowContext(ctx, `SELECT `+outboxColumns+`
FROM usage_ledger_outbox WHERE `+predicate+` FOR UPDATE`, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return event, err
}

func sameOutboxFact(left, right *commerce.OutboxEvent) bool {
	return left != nil && right != nil && left.TenantID == right.TenantID &&
		left.Type == right.Type && left.AggregateType == right.AggregateType &&
		left.AggregateID == right.AggregateID && left.AggregateVersion == right.AggregateVersion &&
		left.IdempotencyKey == right.IdempotencyKey && left.PayloadDigest == right.PayloadDigest
}

func (s *Store) ClaimOutbox(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("usageledger/postgres: invalid outbox claim")
	}
	var claimed []*commerce.OutboxEvent
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		claimed, err = claimOutboxTx(ctx, tx, owner, now, lease, limit)
		return err
	})
	return claimed, err
}

func claimOutboxTx(
	ctx context.Context, tx *sql.Tx, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+outboxColumns+` FROM usage_ledger_outbox
WHERE (status='pending' AND next_attempt_at_ns <= $1)
   OR (status='leased' AND lease_until_ns <= $1)
ORDER BY created_at_ns, id LIMIT $2 FOR UPDATE SKIP LOCKED`, timeNano(now), limit)
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: claim outbox: %w", err)
	}
	events, err := readOutboxRows(rows)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		if err := leaseOutboxTx(ctx, tx, event, owner, now, lease); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func leaseOutboxTx(
	ctx context.Context, tx *sql.Tx, event *commerce.OutboxEvent,
	owner string, now time.Time, lease time.Duration,
) error {
	_, err := tx.ExecContext(ctx, `UPDATE usage_ledger_outbox SET
status='leased', lease_owner=$2, lease_until_ns=$3, attempts=attempts+1 WHERE id=$1`,
		event.ID, owner, timeNano(now.Add(lease)))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: lease outbox: %w", err)
	}
	event.Status, event.LeaseOwner, event.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
	event.Attempts++
	return nil
}

func readOutboxRows(rows *sql.Rows) ([]*commerce.OutboxEvent, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.OutboxEvent, 0)
	for rows.Next() {
		event, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("usageledger/postgres: scan outbox: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) CompleteOutbox(ctx context.Context, id, owner string, deliveredAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE usage_ledger_outbox SET
status='delivered', delivered_at_ns=$3, lease_owner='', lease_until_ns=0
WHERE id=$1 AND status='leased' AND lease_owner=$2`, id, owner, timeNano(deliveredAt))
	return s.classifyOutboxUpdate(ctx, result, err, id, "complete")
}

func (s *Store) FailOutbox(
	ctx context.Context, id, owner, reason string, now, nextAttempt time.Time, maxAttempts int,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE usage_ledger_outbox SET
status=CASE WHEN $5 > 0 AND attempts >= $5 THEN 'dead' ELSE 'pending' END,
next_attempt_at_ns=CASE WHEN $5 > 0 AND attempts >= $5 THEN next_attempt_at_ns ELSE $4 END,
last_error=$3, lease_owner='', lease_until_ns=0
WHERE id=$1 AND status='leased' AND lease_owner=$2`,
		id, owner, boundedOutboxError(reason), timeNano(nextAttempt), maxAttempts)
	_ = now
	return s.classifyOutboxUpdate(ctx, result, err, id, "fail")
}

func (s *Store) QuarantineOutbox(
	ctx context.Context, id, owner, reason string, now time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE usage_ledger_outbox SET
status='quarantined', last_error=$3, lease_owner='', lease_until_ns=0
WHERE id=$1 AND status='leased' AND lease_owner=$2`, id, owner, boundedOutboxError(reason))
	_ = now
	return s.classifyOutboxUpdate(ctx, result, err, id, "quarantine")
}

func (s *Store) classifyOutboxUpdate(
	ctx context.Context, result sql.Result, err error, id, operation string,
) error {
	if err != nil {
		return fmt.Errorf("usageledger/postgres: %s outbox: %w", operation, err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated == 1 {
		return err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM usage_ledger_outbox WHERE id=$1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("usageledger/postgres: inspect outbox update: %w", err)
	}
	if !exists {
		return commerce.ErrOutboxNotFound
	}
	return commerce.ErrOutboxLeaseLost
}

func (s *Store) ListDeadOutbox(ctx context.Context, limit int) ([]*commerce.OutboxEvent, error) {
	query := `SELECT ` + outboxColumns + ` FROM usage_ledger_outbox
WHERE status IN ('dead','quarantined') ORDER BY created_at_ns, id`
	args := []any{}
	if limit > 0 {
		query, args = query+` LIMIT $1`, []any{limit}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: list dead outbox: %w", err)
	}
	return readOutboxRows(rows)
}

func (s *Store) ReplayOutbox(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE usage_ledger_outbox SET
status='pending', attempts=0, next_attempt_at_ns=$2, last_error='', lease_owner='', lease_until_ns=0
WHERE id=$1 AND status IN ('dead','quarantined')`, id, timeNano(now))
	return s.classifyOutboxUpdate(ctx, result, err, id, "replay")
}

func boundedOutboxError(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 1024 {
		return reason[:1024]
	}
	return reason
}
