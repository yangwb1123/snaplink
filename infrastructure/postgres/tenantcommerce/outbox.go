package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

const outboxColumns = `id, tenant_id, event_type, aggregate_type, aggregate_id,
aggregate_version, idempotency_key, occurred_at_ns, payload, payload_digest,
status, attempts, next_attempt_at_ns, lease_owner, lease_until_ns, last_error,
delivered_at_ns, created_at_ns`

const quotaDeliveryColumns = `o.id, o.tenant_id, o.event_type, o.aggregate_type, o.aggregate_id,
o.aggregate_version, o.idempotency_key, o.occurred_at_ns, o.payload, o.payload_digest,
q.status, q.attempts, q.next_attempt_at_ns, q.lease_owner, q.lease_until_ns, q.last_error,
q.delivered_at_ns, o.created_at_ns`

func validateOutboxEvents(events []*commerce.OutboxEvent) error {
	for _, event := range events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func versionedOutboxEvents(events []*commerce.OutboxEvent, version uint64) []*commerce.OutboxEvent {
	result := make([]*commerce.OutboxEvent, 0, len(events))
	for _, event := range events {
		copy := *event
		copy.Payload = maps.Clone(event.Payload)
		if copy.AggregateType == "wallet" {
			copy.AggregateVersion = version
		}
		result = append(result, &copy)
	}
	return result
}

func insertOutboxEventsTx(ctx context.Context, tx *sql.Tx, events []*commerce.OutboxEvent) error {
	if err := validateOutboxEvents(events); err != nil {
		return err
	}
	for _, event := range events {
		if err := insertOutboxEventTx(ctx, tx, event); err != nil {
			return err
		}
	}
	return nil
}

func insertOutboxEventTx(ctx context.Context, tx *sql.Tx, event *commerce.OutboxEvent) error {
	payload, err := encodeJSON(event.Payload)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_outbox (
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
		return fmt.Errorf("tenantcommerce/postgres: insert outbox: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if inserted == 0 {
		if err := ensureOutboxFactTx(ctx, tx, event); err != nil {
			return err
		}
	}
	return insertQuotaProjectionDeliveryTx(ctx, tx, event)
}

func insertQuotaProjectionDeliveryTx(ctx context.Context, tx *sql.Tx, event *commerce.OutboxEvent) error {
	if event.Type != commerce.EventEntitlementPublished {
		return nil
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_quota_outbox (
event_id, tenant_id, projection_revision, status, attempts, next_attempt_at_ns,
lease_owner, lease_until_ns, last_error, delivered_revision, delivered_at_ns
) VALUES ($1,$2,$3,'pending',0,0,'',0,'',0,0) ON CONFLICT (event_id) DO NOTHING`,
		event.ID, event.TenantID, event.AggregateVersion)
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: insert quota projection outbox: %w", err)
	}
	return nil
}

func ensureOutboxReplayTx(ctx context.Context, tx *sql.Tx, events []*commerce.OutboxEvent) error {
	for _, event := range events {
		if err := ensureOutboxFactTx(ctx, tx, event); err != nil {
			return err
		}
	}
	return nil
}

func ensureOutboxFactTx(ctx context.Context, tx *sql.Tx, expected *commerce.OutboxEvent) error {
	byID, idErr := findOutboxFactTx(ctx, tx, `id=$1`, expected.ID)
	if idErr != nil {
		return idErr
	}
	byKey, keyErr := findOutboxFactTx(
		ctx, tx, `tenant_id=$1 AND idempotency_key=$2`, expected.TenantID, expected.IdempotencyKey,
	)
	if keyErr != nil {
		return keyErr
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

func findOutboxFactTx(
	ctx context.Context, tx *sql.Tx, predicate string, args ...any,
) (*commerce.OutboxEvent, error) {
	row := tx.QueryRowContext(ctx, `SELECT `+outboxColumns+` FROM tenant_commerce_outbox
WHERE `+predicate+` FOR UPDATE`, args...)
	event, err := scanOutbox(row)
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
		return nil, errors.New("tenantcommerce/postgres: invalid outbox claim")
	}
	var claimed []*commerce.OutboxEvent
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		var claimErr error
		claimed, claimErr = claimOutboxTx(ctx, tx, owner, now, lease, limit)
		return claimErr
	})
	return claimed, err
}

func claimOutboxTx(
	ctx context.Context, tx *sql.Tx, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+outboxColumns+` FROM tenant_commerce_outbox
WHERE (status='pending' AND next_attempt_at_ns <= $1)
   OR (status='leased' AND lease_until_ns <= $1)
ORDER BY created_at_ns, id LIMIT $2 FOR UPDATE SKIP LOCKED`, timeNano(now), limit)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: claim outbox: %w", err)
	}
	events, err := readOutboxRows(rows)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		_, err = tx.ExecContext(ctx, `UPDATE tenant_commerce_outbox SET
status='leased', lease_owner=$2, lease_until_ns=$3, attempts=attempts+1 WHERE id=$1`,
			event.ID, owner, timeNano(now.Add(lease)))
		if err != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: lease outbox: %w", err)
		}
		event.Status, event.LeaseOwner, event.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
		event.Attempts++
	}
	return events, nil
}

func readOutboxRows(rows *sql.Rows) ([]*commerce.OutboxEvent, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.OutboxEvent, 0)
	for rows.Next() {
		event, err := scanOutbox(rows)
		if err != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: scan outbox: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) CompleteOutbox(ctx context.Context, id, owner string, deliveredAt time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tenant_commerce_outbox SET
status='delivered', delivered_at_ns=$3, lease_owner='', lease_until_ns=0
WHERE id=$1 AND status='leased' AND lease_owner=$2`, id, owner, timeNano(deliveredAt))
	return s.classifyOutboxUpdate(ctx, result, err, id, "complete")
}

func (s *Store) FailOutbox(
	ctx context.Context, id, owner, reason string, now, nextAttempt time.Time, maxAttempts int,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tenant_commerce_outbox SET
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
	result, err := s.db.ExecContext(ctx, `UPDATE tenant_commerce_outbox SET
status='quarantined', last_error=$3, lease_owner='', lease_until_ns=0
WHERE id=$1 AND status='leased' AND lease_owner=$2`, id, owner, boundedOutboxError(reason))
	_ = now
	return s.classifyOutboxUpdate(ctx, result, err, id, "quarantine")
}

func (s *Store) classifyOutboxUpdate(
	ctx context.Context, result sql.Result, err error, id, operation string,
) error {
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: %s outbox: %w", operation, err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated == 1 {
		return err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM tenant_commerce_outbox WHERE id=$1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("tenantcommerce/postgres: inspect outbox update: %w", err)
	}
	if !exists {
		return commerce.ErrOutboxNotFound
	}
	return commerce.ErrOutboxLeaseLost
}

func (s *Store) ListDeadOutbox(ctx context.Context, limit int) ([]*commerce.OutboxEvent, error) {
	query := `SELECT ` + outboxColumns + ` FROM tenant_commerce_outbox
WHERE status IN ('dead','quarantined') ORDER BY created_at_ns, id`
	args := []any{}
	if limit > 0 {
		query, args = query+` LIMIT $1`, []any{limit}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list dead outbox: %w", err)
	}
	return readOutboxRows(rows)
}

func (s *Store) ReplayOutbox(ctx context.Context, id string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tenant_commerce_outbox SET
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

func (s *Store) ClaimQuotaProjectionDeliveries(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("tenantcommerce/postgres: invalid quota projection claim")
	}
	var claimed []*commerce.OutboxEvent
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		var claimErr error
		claimed, claimErr = claimQuotaProjectionDeliveriesTx(ctx, tx, owner, now, lease, limit)
		return claimErr
	})
	return claimed, err
}

func claimQuotaProjectionDeliveriesTx(
	ctx context.Context, tx *sql.Tx, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+quotaDeliveryColumns+`
FROM tenant_commerce_quota_outbox q JOIN tenant_commerce_outbox o ON o.id=q.event_id
WHERE ((q.status='pending' AND q.next_attempt_at_ns <= $1)
   OR (q.status='leased' AND q.lease_until_ns <= $1))
  AND NOT EXISTS (
    SELECT 1 FROM tenant_commerce_quota_outbox older
    JOIN tenant_commerce_outbox older_event ON older_event.id=older.event_id
    WHERE older.tenant_id=q.tenant_id AND older.status <> 'delivered'
      AND (older_event.created_at_ns < o.created_at_ns
        OR (older_event.created_at_ns = o.created_at_ns AND older.event_id < q.event_id)))
ORDER BY o.created_at_ns, o.id LIMIT $2 FOR UPDATE OF q SKIP LOCKED`, timeNano(now), limit)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: claim quota projection outbox: %w", err)
	}
	events, err := readOutboxRows(rows)
	if err != nil {
		return nil, err
	}
	for _, event := range events {
		_, err = tx.ExecContext(ctx, `UPDATE tenant_commerce_quota_outbox SET
status='leased', lease_owner=$2, lease_until_ns=$3, attempts=attempts+1 WHERE event_id=$1`,
			event.ID, owner, timeNano(now.Add(lease)))
		if err != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: lease quota projection outbox: %w", err)
		}
		event.Status, event.LeaseOwner, event.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
		event.Attempts++
	}
	return events, nil
}

func (s *Store) CompleteQuotaProjectionDelivery(
	ctx context.Context, eventID, owner string, revision uint64, deliveredAt time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tenant_commerce_quota_outbox SET
status='delivered', delivered_revision=$3, delivered_at_ns=$4, lease_owner='', lease_until_ns=0
WHERE event_id=$1 AND status='leased' AND lease_owner=$2 AND projection_revision <= $3`,
		eventID, owner, revision, timeNano(deliveredAt))
	return s.classifyQuotaProjectionUpdate(ctx, result, err, eventID, "complete")
}

func (s *Store) FailQuotaProjectionDelivery(
	ctx context.Context, eventID, owner, reason string, _ time.Time, nextAttempt time.Time,
) error {
	result, err := s.db.ExecContext(ctx, `UPDATE tenant_commerce_quota_outbox SET
status='pending', next_attempt_at_ns=$4, last_error=$3, lease_owner='', lease_until_ns=0
WHERE event_id=$1 AND status='leased' AND lease_owner=$2`,
		eventID, owner, boundedOutboxError(reason), timeNano(nextAttempt))
	return s.classifyQuotaProjectionUpdate(ctx, result, err, eventID, "fail")
}

func (s *Store) classifyQuotaProjectionUpdate(
	ctx context.Context, result sql.Result, err error, eventID, operation string,
) error {
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: %s quota projection outbox: %w", operation, err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated == 1 {
		return err
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM tenant_commerce_quota_outbox WHERE event_id=$1)`, eventID).Scan(&exists); err != nil {
		return fmt.Errorf("tenantcommerce/postgres: inspect quota projection outbox: %w", err)
	}
	if !exists {
		return commerce.ErrOutboxNotFound
	}
	return commerce.ErrOutboxLeaseLost
}

func (s *Store) QuotaProjectionDeliveryReady(
	ctx context.Context, now time.Time, maxLag time.Duration,
) error {
	if maxLag <= 0 {
		return commerce.ErrQuotaProjectionLag
	}
	var lagged bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
SELECT 1 FROM tenant_commerce_quota_outbox q
JOIN tenant_commerce_outbox o ON o.id=q.event_id
WHERE q.status <> 'delivered' AND o.created_at_ns <= $1)`, timeNano(now.Add(-maxLag))).Scan(&lagged)
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: inspect quota projection lag: %w", err)
	}
	if lagged {
		return commerce.ErrQuotaProjectionLag
	}
	return nil
}
