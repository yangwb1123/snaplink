package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
)

const walletColumns = `tenant_id, currency, balance_minor, status, version, updated_at_ns`

const ledgerColumns = `id, tenant_id, currency, kind, amount_minor, balance_after,
wallet_version, idempotency_key, reference, occurred_at_ns, created_at_ns`

func (s *Store) PostLedgerEntry(
	ctx context.Context, mutation commerce.WalletMutation,
) (*commerce.LedgerEntry, *commerce.Wallet, error) {
	if err := validateWalletMutation(mutation); err != nil {
		return nil, nil, err
	}
	var entry *commerce.LedgerEntry
	var wallet *commerce.Wallet
	err := postgresbackend.RunSerializable(ctx, s.db, func(tx *sql.Tx) error {
		var applyErr error
		var replay bool
		entry, wallet, replay, applyErr = applyLedgerTx(ctx, tx, mutation.Entry)
		if applyErr != nil {
			return applyErr
		}
		if replay {
			return nil
		}
		events := versionedOutboxEvents(mutation.Events, wallet.Version)
		return insertOutboxEventsTx(ctx, tx, events)
	})
	if uniqueConstraint(err) != "" {
		return s.replayLedgerAfterConflict(ctx, mutation.Entry)
	}
	return entry, wallet, err
}

func validateWalletMutation(mutation commerce.WalletMutation) error {
	if err := mutation.Entry.Validate(); err != nil {
		return err
	}
	if len(mutation.Events) == 0 {
		return errors.New("tenantcommerce/postgres: wallet outbox event required")
	}
	return validateOutboxEvents(mutation.Events)
}

func applyLedgerTx(
	ctx context.Context, tx *sql.Tx, requested *commerce.LedgerEntry,
) (*commerce.LedgerEntry, *commerce.Wallet, bool, error) {
	current, err := findLedgerReplayTx(ctx, tx, requested, true)
	if err != nil {
		return nil, nil, false, err
	}
	if current != nil {
		wallet, walletErr := getWalletTx(ctx, tx, requested.TenantID, requested.Currency, true)
		return current, wallet, true, walletErr
	}
	wallet, err := lockWalletTx(ctx, tx, requested.TenantID, requested.Currency)
	if err != nil {
		return nil, nil, false, err
	}
	if wallet.Status == commerce.WalletFrozen && requested.AmountMinor < 0 {
		return nil, nil, false, commerce.ErrWalletFrozen
	}
	balance, err := nextBalance(wallet.BalanceMinor, requested.AmountMinor)
	if err != nil {
		return nil, nil, false, err
	}
	entry, nextWallet := nextWalletState(requested, wallet, balance)
	if err := updateWalletTx(ctx, tx, nextWallet); err != nil {
		return nil, nil, false, err
	}
	if err := insertLedgerTx(ctx, tx, entry); err != nil {
		return nil, nil, false, err
	}
	return entry, nextWallet, false, nil
}

func findLedgerReplayTx(
	ctx context.Context, query subscriptionQuery, requested *commerce.LedgerEntry, lock bool,
) (*commerce.LedgerEntry, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	row := query.QueryRowContext(ctx, `SELECT `+ledgerColumns+` FROM tenant_commerce_ledger
WHERE tenant_id=$1 AND currency=$2 AND idempotency_key=$3`+suffix,
		requested.TenantID, requested.Currency, requested.IdempotencyKey)
	current, err := scanLedger(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: find ledger replay: %w", err)
	}
	if !sameLedgerCommand(current, requested) {
		return nil, commerce.ErrIdempotencyConflict
	}
	return current, nil
}

func (s *Store) replayLedgerAfterConflict(
	ctx context.Context, requested *commerce.LedgerEntry,
) (*commerce.LedgerEntry, *commerce.Wallet, error) {
	entry, err := findLedgerReplayTx(ctx, s.db, requested, false)
	if err != nil {
		return nil, nil, err
	}
	if entry == nil {
		return nil, nil, commerce.ErrIdempotencyConflict
	}
	wallet, err := s.GetWallet(ctx, requested.TenantID, requested.Currency)
	return entry, wallet, err
}

func lockWalletTx(ctx context.Context, tx *sql.Tx, tenantID, currency string) (*commerce.Wallet, error) {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_wallets
(tenant_id, currency, balance_minor, status, version, updated_at_ns) VALUES ($1,$2,0,'active',0,0)
ON CONFLICT (tenant_id, currency) DO NOTHING`, tenantID, currency)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: ensure wallet: %w", err)
	}
	return getWalletTx(ctx, tx, tenantID, currency, true)
}

func updateWalletTx(ctx context.Context, tx *sql.Tx, wallet *commerce.Wallet) error {
	result, err := tx.ExecContext(ctx, `UPDATE tenant_commerce_wallets SET
balance_minor=$3, status=$4, version=$5, updated_at_ns=$6 WHERE tenant_id=$1 AND currency=$2`,
		wallet.TenantID, wallet.Currency, wallet.BalanceMinor, wallet.Status,
		wallet.Version, timeNano(wallet.UpdatedAt))
	if err != nil {
		return fmt.Errorf("tenantcommerce/postgres: update wallet: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return fmt.Errorf("tenantcommerce/postgres: update wallet affected %d rows: %w", updated, err)
	}
	return nil
}

func insertLedgerTx(ctx context.Context, tx *sql.Tx, entry *commerce.LedgerEntry) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_commerce_ledger (
id, tenant_id, currency, kind, amount_minor, balance_after, wallet_version,
idempotency_key, reference, occurred_at_ns, created_at_ns
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		entry.ID, entry.TenantID, entry.Currency, entry.Kind, entry.AmountMinor, entry.BalanceAfter,
		entry.WalletVersion, entry.IdempotencyKey, entry.Reference, timeNano(entry.OccurredAt),
		timeNano(entry.CreatedAt),
	)
	return wrapWrite("insert ledger entry", err)
}

func nextBalance(balance, amount int64) (int64, error) {
	if amount > 0 && balance > math.MaxInt64-amount {
		return 0, commerce.ErrWalletOverflow
	}
	if amount < 0 && balance < math.MinInt64-amount {
		return 0, commerce.ErrWalletOverflow
	}
	next := balance + amount
	if next < 0 {
		return 0, commerce.ErrInsufficientFunds
	}
	return next, nil
}

func nextWalletState(
	entry *commerce.LedgerEntry, wallet *commerce.Wallet, balance int64,
) (*commerce.LedgerEntry, *commerce.Wallet) {
	nextEntry, nextWallet := *entry, *wallet
	nextWallet.BalanceMinor, nextWallet.Version = balance, wallet.Version+1
	nextWallet.UpdatedAt = entry.CreatedAt
	nextEntry.BalanceAfter, nextEntry.WalletVersion = balance, nextWallet.Version
	return &nextEntry, &nextWallet
}

func sameLedgerCommand(left, right *commerce.LedgerEntry) bool {
	return left.TenantID == right.TenantID && left.Currency == right.Currency &&
		left.Kind == right.Kind && left.AmountMinor == right.AmountMinor && left.Reference == right.Reference
}

type walletQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func getWalletTx(
	ctx context.Context, query walletQuery, tenantID, currency string, lock bool,
) (*commerce.Wallet, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	row := query.QueryRowContext(ctx, `SELECT `+walletColumns+` FROM tenant_commerce_wallets
WHERE tenant_id=$1 AND currency=$2`+suffix, tenantID, currency)
	wallet, err := scanWallet(row)
	return wallet, err
}

func (s *Store) GetWallet(ctx context.Context, tenantID, currency string) (*commerce.Wallet, error) {
	wallet, err := getWalletTx(ctx, s.db, tenantID, currency, false)
	if errors.Is(err, sql.ErrNoRows) {
		return &commerce.Wallet{TenantID: tenantID, Currency: currency, Status: commerce.WalletActive}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: get wallet: %w", err)
	}
	return wallet, nil
}

func (s *Store) ListLedgerEntries(
	ctx context.Context, tenantID, currency string, limit int,
) ([]*commerce.LedgerEntry, error) {
	query := `SELECT ` + ledgerColumns + ` FROM tenant_commerce_ledger
WHERE tenant_id=$1 AND currency=$2 ORDER BY wallet_version DESC`
	args := []any{tenantID, currency}
	if limit > 0 {
		query, args = query+` LIMIT $3`, append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("tenantcommerce/postgres: list ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	result := make([]*commerce.LedgerEntry, 0)
	for rows.Next() {
		entry, scanErr := scanLedger(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("tenantcommerce/postgres: scan ledger: %w", scanErr)
		}
		result = append(result, entry)
	}
	return result, rows.Err()
}
