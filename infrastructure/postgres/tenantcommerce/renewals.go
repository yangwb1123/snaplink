package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

func (s *Store) ClaimDueRenewals(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.RenewalClaim, error) {
	if owner == "" || now.IsZero() || lease <= 0 || limit <= 0 {
		return nil, commerce.ErrInvalidRenewal
	}
	var claims []*commerce.RenewalClaim
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		var claimErr error
		claims, claimErr = claimDueRenewalsTx(ctx, tx, owner, now, lease, limit)
		return claimErr
	})
	return claims, err
}

func claimDueRenewalsTx(
	ctx context.Context, tx *sql.Tx, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.RenewalClaim, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+subscriptionColumns+`
FROM tenant_commerce_subscriptions
WHERE status IN ('active', 'trialing', 'past_due')
  AND billing_interval IN ('month', 'year')
  AND current_period_end_ns <= $1
  AND renewal_next_attempt_at_ns <= $1
  AND renewal_lease_until_ns <= $1
ORDER BY renewal_next_attempt_at_ns, id LIMIT $2 FOR UPDATE SKIP LOCKED`, timeNano(now), limit)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: claim renewals: %w", err)
	}
	subscriptions, err := readSubscriptionRows(rows)
	if err != nil {
		return nil, err
	}
	return leaseRenewalsTx(ctx, tx, subscriptions, owner, now.Add(lease))
}

func (s *Store) InspectRenewalBacklog(
	ctx context.Context, now time.Time,
) (commerce.RenewalBacklog, error) {
	if now.IsZero() {
		return commerce.RenewalBacklog{}, commerce.ErrInvalidRenewal
	}
	var backlog commerce.RenewalBacklog
	var oldest int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*),
    COALESCE(MIN(GREATEST(current_period_end_ns, renewal_next_attempt_at_ns)), 0)
FROM tenant_commerce_subscriptions
WHERE status IN ('active', 'trialing', 'past_due')
  AND billing_interval IN ('month', 'year')
  AND current_period_end_ns <= $1
  AND renewal_next_attempt_at_ns <= $1`, timeNano(now)).Scan(&backlog.DueCount, &oldest)
	if err != nil {
		return commerce.RenewalBacklog{}, fmt.Errorf("tenantcommerce/postgres: inspect renewal backlog: %w", err)
	}
	backlog.OldestDueAt = nanoTime(oldest)
	return backlog, nil
}

func readSubscriptionRows(rows *sql.Rows) ([]*commerce.Subscription, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.Subscription, 0)
	for rows.Next() {
		subscription, err := scanSubscription(rows)
		if err != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: scan renewal: %w", err)
		}
		result = append(result, subscription)
	}
	return result, rows.Err()
}

func leaseRenewalsTx(
	ctx context.Context, tx *sql.Tx, subscriptions []*commerce.Subscription,
	owner string, until time.Time,
) ([]*commerce.RenewalClaim, error) {
	claims := make([]*commerce.RenewalClaim, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		_, err := tx.ExecContext(ctx, `UPDATE tenant_commerce_subscriptions
SET renewal_lease_owner=$2, renewal_lease_until_ns=$3 WHERE id=$1`,
			subscription.ID, owner, timeNano(until))
		if err != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: lease renewal: %w", err)
		}
		claims = append(claims, &commerce.RenewalClaim{
			Subscription: subscription, Owner: owner, LeaseUntil: until,
		})
	}
	return claims, nil
}

type encodedRenewal struct {
	successFeatures, successLimits string
	failureFeatures, failureLimits string
}

func (s *Store) ApplyRenewal(
	ctx context.Context, mutation commerce.RenewalMutation,
) (*commerce.RenewalResult, error) {
	if err := mutation.Validate(); err != nil {
		return nil, err
	}
	encoded, err := encodeRenewal(mutation)
	if err != nil {
		return nil, err
	}
	var result *commerce.RenewalResult
	err = postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		var applyErr error
		result, applyErr = s.applyRenewalTx(ctx, tx, mutation, encoded)
		return applyErr
	})
	return result, err
}

func encodeRenewal(mutation commerce.RenewalMutation) (encodedRenewal, error) {
	successFeatures, successLimits, err := encodeEntitlement(*mutation.Success)
	if err != nil {
		return encodedRenewal{}, err
	}
	encoded := encodedRenewal{successFeatures: successFeatures, successLimits: successLimits}
	if mutation.Insufficient == nil {
		return encoded, nil
	}
	failureFeatures, failureLimits, err := encodeEntitlement(*mutation.Insufficient)
	encoded.failureFeatures, encoded.failureLimits = failureFeatures, failureLimits
	return encoded, err
}

func (s *Store) applyRenewalTx(
	ctx context.Context, tx *sql.Tx, mutation commerce.RenewalMutation, encoded encodedRenewal,
) (*commerce.RenewalResult, error) {
	current, err := validateRenewalClaimTx(ctx, tx, mutation)
	if err != nil {
		return nil, err
	}
	if mutation.Debit == nil {
		return writeRenewalBranchTx(ctx, tx, mutation.ClaimUntil, mutation.Success, mutation.SuccessOutcome,
			nil, nil, encoded.successFeatures, encoded.successLimits)
	}
	wallet, err := lockWalletTx(ctx, tx, current.TenantID, mutation.Debit.Currency)
	if err != nil {
		return nil, err
	}
	if wallet.Status == commerce.WalletFrozen {
		return nil, commerce.ErrWalletFrozen
	}
	if _, err := nextBalance(wallet.BalanceMinor, mutation.Debit.AmountMinor); err != nil {
		if errors.Is(err, commerce.ErrInsufficientFunds) {
			return writeRenewalBranchTx(ctx, tx, mutation.ClaimUntil, mutation.Insufficient, mutation.InsufficientOutcome,
				nil, wallet, encoded.failureFeatures, encoded.failureLimits)
		}
		return nil, err
	}
	return s.applyFundedRenewalTx(ctx, tx, mutation, encoded)
}

func (s *Store) applyFundedRenewalTx(
	ctx context.Context, tx *sql.Tx, mutation commerce.RenewalMutation, encoded encodedRenewal,
) (*commerce.RenewalResult, error) {
	entry, wallet, replay, err := applyLedgerTx(ctx, tx, mutation.Debit)
	if err != nil {
		return nil, err
	}
	if replay {
		return nil, commerce.ErrIdempotencyConflict
	}
	return writeRenewalBranchTx(ctx, tx, mutation.ClaimUntil, mutation.Success, mutation.SuccessOutcome,
		entry, wallet, encoded.successFeatures, encoded.successLimits)
}

func validateRenewalClaimTx(
	ctx context.Context, tx *sql.Tx, mutation commerce.RenewalMutation,
) (*commerce.Subscription, error) {
	current, err := getSubscriptionTx(ctx, tx, mutation.Success.Subscription.ID, true)
	if err != nil {
		return nil, err
	}
	var owner string
	var leaseUntil int64
	err = tx.QueryRowContext(ctx, `SELECT renewal_lease_owner, renewal_lease_until_ns
FROM tenant_commerce_subscriptions WHERE id=$1`, current.ID).Scan(&owner, &leaseUntil)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: read renewal lease: %w", err)
	}
	leaseTime := nanoTime(leaseUntil)
	if owner != mutation.Owner || !leaseTime.Equal(mutation.ClaimUntil) ||
		!leaseTime.After(mutation.AttemptedAt) {
		return nil, commerce.ErrRenewalClaimLost
	}
	if err := requireActiveRenewalLeaseTx(ctx, tx, leaseTime); err != nil {
		return nil, err
	}
	if current.Revision != mutation.ExpectedRevision ||
		!current.CurrentPeriodEnd.Equal(mutation.ExpectedPeriodEnd) ||
		!sameRenewalIdentity(current, mutation.Success.Subscription) {
		return nil, commerce.ErrRevisionConflict
	}
	return current, nil
}

func sameRenewalIdentity(current, next *commerce.Subscription) bool {
	return current.ID == next.ID && current.TenantID == next.TenantID &&
		current.Plan == next.Plan && current.Renewal == next.Renewal &&
		current.CreatedAt.Equal(next.CreatedAt)
}

func writeRenewalBranchTx(
	ctx context.Context, tx *sql.Tx, leaseUntil time.Time, branch *commerce.SubscriptionMutation,
	outcome commerce.RenewalOutcome, entry *commerce.LedgerEntry, wallet *commerce.Wallet,
	features, limits string,
) (*commerce.RenewalResult, error) {
	if err := requireActiveRenewalLeaseTx(ctx, tx, leaseUntil); err != nil {
		return nil, err
	}
	if err := writeSubscriptionTx(ctx, tx, branch.Subscription, true); err != nil {
		return nil, err
	}
	if err := writeEntitlementTx(ctx, tx, branch.Entitlement, features, limits); err != nil {
		return nil, err
	}
	events := branch.Events
	if wallet != nil {
		events = versionedOutboxEvents(events, wallet.Version)
	}
	if err := insertOutboxEventsTx(ctx, tx, events); err != nil {
		return nil, err
	}
	return &commerce.RenewalResult{
		Outcome: outcome, Subscription: branch.Subscription, Entitlement: branch.Entitlement,
		LedgerEntry: entry, Wallet: wallet,
	}, nil
}

func requireActiveRenewalLeaseTx(ctx context.Context, tx *sql.Tx, leaseUntil time.Time) error {
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT statement_timestamp()`).Scan(&databaseNow); err != nil {
		return fmt.Errorf("tenantcommerce/postgres: read renewal clock: %w", err)
	}
	if !leaseUntil.After(databaseNow) {
		return commerce.ErrRenewalClaimLost
	}
	return nil
}
