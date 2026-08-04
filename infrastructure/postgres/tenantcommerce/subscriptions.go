package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

const subscriptionColumns = `id, tenant_id, plan_id, plan_version,
billing_interval, renewal_currency, renewal_price_minor, renewal_grace_days, status,
current_period_start_ns, current_period_end_ns, trial_end_ns, grace_until_ns,
cancel_at_period_end, canceled_at_ns, provider, provider_subscription_id,
renewal_next_attempt_at_ns, revision, created_at_ns, updated_at_ns`

const entitlementColumns = `tenant_id, subscription_id, plan_id, plan_version,
revision, active, features, limits, effective_at_ns, expires_at_ns, generated_at_ns`

func (s *Store) ApplySubscription(ctx context.Context, mutation commerce.SubscriptionMutation) error {
	features, limits, err := encodeEntitlement(mutation)
	if err != nil {
		return err
	}
	err = postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		return s.applySubscriptionTx(ctx, tx, mutation, features, limits)
	})
	constraint := uniqueConstraint(err)
	if constraint == "" {
		return err
	}
	if replayErr := s.subscriptionReplayAfterConflict(ctx, mutation); replayErr == nil {
		return nil
	}
	if constraint == "idx_tenant_commerce_one_live_subscription" {
		return commerce.ErrTenantSubscribed
	}
	return commerce.ErrIdempotencyConflict
}

func (s *Store) subscriptionReplayAfterConflict(
	ctx context.Context, mutation commerce.SubscriptionMutation,
) error {
	return postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		current, err := getSubscriptionTx(ctx, tx, mutation.Subscription.ID, true)
		if err != nil {
			return err
		}
		if !sameSubscription(current, mutation.Subscription) {
			return commerce.ErrIdempotencyConflict
		}
		return ensureOutboxReplayTx(ctx, tx, mutation.Events)
	})
}

func encodeEntitlement(mutation commerce.SubscriptionMutation) (string, string, error) {
	if err := validateSubscriptionMutation(mutation); err != nil {
		return "", "", err
	}
	features, err := encodeJSON(mutation.Entitlement.Features)
	if err != nil {
		return "", "", err
	}
	limits, err := encodeJSON(mutation.Entitlement.Limits)
	return features, limits, err
}

func validateSubscriptionMutation(mutation commerce.SubscriptionMutation) error {
	if err := mutation.Subscription.Validate(); err != nil {
		return err
	}
	entitlement := mutation.Entitlement
	subscription := mutation.Subscription
	if entitlement == nil || entitlement.TenantID != subscription.TenantID ||
		entitlement.SubscriptionID != subscription.ID || entitlement.Plan != subscription.Plan ||
		entitlement.Revision != subscription.Revision {
		return errors.New("tenantcommerce/postgres: entitlement revision mismatch")
	}
	if len(mutation.Events) == 0 {
		return errors.New("tenantcommerce/postgres: subscription outbox event required")
	}
	return validateOutboxEvents(mutation.Events)
}

func (s *Store) applySubscriptionTx(
	ctx context.Context, tx *sql.Tx, mutation commerce.SubscriptionMutation, features, limits string,
) error {
	current, err := getSubscriptionTx(ctx, tx, mutation.Subscription.ID, true)
	if err != nil && !errors.Is(err, commerce.ErrSubscriptionNotFound) {
		return err
	}
	if current != nil && sameSubscription(current, mutation.Subscription) {
		return ensureOutboxReplayTx(ctx, tx, mutation.Events)
	}
	if err := validateSubscriptionRevision(current, mutation); err != nil {
		return err
	}
	if current != nil && (current.TenantID != mutation.Subscription.TenantID ||
		!current.CreatedAt.Equal(mutation.Subscription.CreatedAt)) {
		return commerce.ErrInvalidSubscription
	}
	if err := rejectOtherLiveSubscription(ctx, tx, mutation.Subscription); err != nil {
		return err
	}
	if err := writeSubscriptionTx(ctx, tx, mutation.Subscription, current != nil); err != nil {
		return err
	}
	if err := writeEntitlementTx(ctx, tx, mutation.Entitlement, features, limits); err != nil {
		return err
	}
	return insertOutboxEventsTx(ctx, tx, mutation.Events)
}

func validateSubscriptionRevision(current *commerce.Subscription, mutation commerce.SubscriptionMutation) error {
	if current == nil {
		if mutation.ExpectedRevision != 0 || mutation.Subscription.Revision != 1 {
			return commerce.ErrRevisionConflict
		}
		return nil
	}
	if current.Revision != mutation.ExpectedRevision || mutation.Subscription.Revision != current.Revision+1 {
		return commerce.ErrRevisionConflict
	}
	return nil
}

func rejectOtherLiveSubscription(ctx context.Context, tx *sql.Tx, subscription *commerce.Subscription) error {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT id FROM tenant_commerce_subscriptions
WHERE tenant_id = $1 AND id <> $2 AND status NOT IN ('canceled', 'expired')
LIMIT 1 FOR UPDATE`, subscription.TenantID, subscription.ID).Scan(&id)
	if err == nil {
		return commerce.ErrTenantSubscribed
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return fmt.Errorf("tenantcommerce/postgres: lock tenant subscription: %w", err)
}

func writeSubscriptionTx(ctx context.Context, tx *sql.Tx, value *commerce.Subscription, exists bool) error {
	if !exists {
		_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_subscriptions (
id, tenant_id, plan_id, plan_version, status, current_period_start_ns, current_period_end_ns,
trial_end_ns, grace_until_ns, cancel_at_period_end, canceled_at_ns, provider,
provider_subscription_id, revision, created_at_ns, updated_at_ns, billing_interval,
renewal_currency, renewal_price_minor, renewal_grace_days, renewal_next_attempt_at_ns
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`, subscriptionArgs(value)...)
		return wrapWrite("insert subscription", err)
	}
	_, err := tx.ExecContext(ctx, `UPDATE tenant_commerce_subscriptions SET
tenant_id=$2, plan_id=$3, plan_version=$4, status=$5, current_period_start_ns=$6,
current_period_end_ns=$7, trial_end_ns=$8, grace_until_ns=$9, cancel_at_period_end=$10,
canceled_at_ns=$11, provider=$12, provider_subscription_id=$13, revision=$14,
created_at_ns=$15, updated_at_ns=$16, billing_interval=$17, renewal_currency=$18,
renewal_price_minor=$19, renewal_grace_days=$20, renewal_next_attempt_at_ns=$21,
renewal_lease_owner='', renewal_lease_until_ns=0 WHERE id=$1`, subscriptionArgs(value)...)
	return wrapWrite("update subscription", err)
}

func subscriptionArgs(value *commerce.Subscription) []any {
	return []any{
		value.ID, value.TenantID, value.Plan.ID, value.Plan.Version, value.Status,
		timeNano(value.CurrentPeriodStart), timeNano(value.CurrentPeriodEnd), timeNano(value.TrialEnd),
		timeNano(value.GraceUntil), value.CancelAtPeriodEnd, timeNano(value.CanceledAt), value.Provider,
		value.ProviderSubscriptionID, value.Revision, timeNano(value.CreatedAt), timeNano(value.UpdatedAt),
		value.Renewal.Interval, value.Renewal.Price.Currency, value.Renewal.Price.MinorUnits,
		value.Renewal.GracePeriodDays, timeNano(value.RenewalNextAttemptAt),
	}
}

func writeEntitlementTx(
	ctx context.Context, tx *sql.Tx, value *commerce.EntitlementSnapshot, features, limits string,
) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_entitlements (
tenant_id, subscription_id, plan_id, plan_version, revision, active, features, limits,
effective_at_ns, expires_at_ns, generated_at_ns
) VALUES ($1,$2,$3,$4,$5,$6,CAST($7 AS JSONB),CAST($8 AS JSONB),$9,$10,$11)
ON CONFLICT (tenant_id) DO UPDATE SET subscription_id=EXCLUDED.subscription_id,
plan_id=EXCLUDED.plan_id, plan_version=EXCLUDED.plan_version, revision=EXCLUDED.revision,
active=EXCLUDED.active, features=EXCLUDED.features, limits=EXCLUDED.limits,
effective_at_ns=EXCLUDED.effective_at_ns, expires_at_ns=EXCLUDED.expires_at_ns,
generated_at_ns=EXCLUDED.generated_at_ns`,
		value.TenantID, value.SubscriptionID, value.Plan.ID, value.Plan.Version, value.Revision,
		value.Active, features, limits, timeNano(value.EffectiveAt), timeNano(value.ExpiresAt),
		timeNano(value.GeneratedAt),
	)
	return wrapWrite("write entitlement", err)
}

func (s *Store) GetSubscription(ctx context.Context, id string) (*commerce.Subscription, error) {
	value, err := getSubscriptionTx(ctx, s.db, id, false)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: get subscription: %w", err)
	}
	return value, nil
}

type subscriptionQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getSubscriptionTx(
	ctx context.Context, query subscriptionQuery, id string, lock bool,
) (*commerce.Subscription, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	row := query.QueryRowContext(ctx, `SELECT `+subscriptionColumns+`
FROM tenant_commerce_subscriptions WHERE id = $1`+suffix, id)
	value, err := scanSubscription(row)
	return value, notFound(err, commerce.ErrSubscriptionNotFound)
}

func (s *Store) ListSubscriptionsByTenant(
	ctx context.Context, tenantID string,
) ([]*commerce.Subscription, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+subscriptionColumns+`
FROM tenant_commerce_subscriptions WHERE tenant_id = $1 ORDER BY created_at_ns, id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list subscriptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.Subscription, 0)
	for rows.Next() {
		value, scanErr := scanSubscription(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: scan subscription: %w", scanErr)
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func (s *Store) CurrentEntitlement(
	ctx context.Context, tenantID string,
) (*commerce.EntitlementSnapshot, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+entitlementColumns+`
FROM tenant_commerce_entitlements WHERE tenant_id = $1`, tenantID)
	value, err := scanEntitlement(row)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: get entitlement: %w",
			notFound(err, commerce.ErrEntitlementNotFound))
	}
	return value, nil
}

func sameSubscription(left, right *commerce.Subscription) bool {
	return sameSubscriptionIdentity(left, right) && sameSubscriptionPeriod(left, right) &&
		sameSubscriptionProvider(left, right) && sameSubscriptionLifecycle(left, right)
}

func sameSubscriptionIdentity(left, right *commerce.Subscription) bool {
	return left.ID == right.ID && left.TenantID == right.TenantID &&
		left.Plan == right.Plan && left.Status == right.Status
}

func sameSubscriptionPeriod(left, right *commerce.Subscription) bool {
	return left.CurrentPeriodStart.Equal(right.CurrentPeriodStart) &&
		left.CurrentPeriodEnd.Equal(right.CurrentPeriodEnd) && left.TrialEnd.Equal(right.TrialEnd) &&
		left.GraceUntil.Equal(right.GraceUntil) && left.CancelAtPeriodEnd == right.CancelAtPeriodEnd &&
		left.CanceledAt.Equal(right.CanceledAt)
}

func sameSubscriptionProvider(left, right *commerce.Subscription) bool {
	return left.Provider == right.Provider && left.ProviderSubscriptionID == right.ProviderSubscriptionID &&
		left.Revision == right.Revision
}

func sameSubscriptionLifecycle(left, right *commerce.Subscription) bool {
	return left.Renewal == right.Renewal &&
		left.RenewalNextAttemptAt.Equal(right.RenewalNextAttemptAt) &&
		left.CreatedAt.Equal(right.CreatedAt) && left.UpdatedAt.Equal(right.UpdatedAt)
}

func wrapWrite(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("tenantcommerce/postgres: %s: %w", operation, err)
}
