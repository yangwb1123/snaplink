// Package sqlite is a SQLite-backed [metering.Aggregator] that queries the
// audit_events table (written by audit/sqlite.Sink, schema v2+) to compute
// per-tenant usage metrics.
//
// It opens the audit DB read-only: no schema migrations are run here;
// the audit/sqlite.Sink owns the schema. The aggregator expects at least
// schema v2 (the tenant_id column); pass the same DSN you give the Sink.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/snaplink/sso/domains/metering"

	_ "modernc.org/sqlite"
)

// Aggregator is the SQLite-backed [metering.Aggregator].
type Aggregator struct {
	db *sql.DB
}

// New opens dsn (the audit SQLite DB) and returns the aggregator.
// Caller owns Close(). The same DSN as the audit/sqlite.Sink is
// recommended — the aggregator issues read-only SELECT queries only.
func New(dsn string) (*Aggregator, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("metering/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("metering/sqlite: ping: %w", err)
	}
	return &Aggregator{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB — shared-pool deployments may pass
// the same connection the audit Sink uses.
func NewWithDB(db *sql.DB) *Aggregator { return &Aggregator{db: db} }

// Close releases the database connection. Idempotent.
func (a *Aggregator) Close() error {
	if a == nil || a.db == nil {
		return nil
	}
	err := a.db.Close()
	a.db = nil
	return err
}

// Usage returns aggregated metrics for tenantID over the period starting
// at start. start is truncated to the UTC period boundary internally so
// callers don't need to align it.
func (a *Aggregator) Usage(ctx context.Context, tenantID string, period metering.UsagePeriod, start time.Time) (*metering.TenantUsage, error) {
	since, until := periodBounds(start, period)

	u := &metering.TenantUsage{
		TenantID:    tenantID,
		Period:      period,
		PeriodStart: since,
	}

	// Logins: login events with outcome=success for this tenant.
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND type='login' AND outcome='success' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		tenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.Logins); err != nil {
		return nil, fmt.Errorf("metering/sqlite: logins: %w", err)
	}

	// TokensIssued: token_issued events for this tenant.
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND type='token_issued' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		tenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.TokensIssued); err != nil {
		return nil, fmt.Errorf("metering/sqlite: tokens_issued: %w", err)
	}

	// ActiveUsers: distinct actor_ids that logged in successfully.
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE tenant_id=? AND type='login' AND outcome='success' AND actor_id!='' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		tenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.ActiveUsers); err != nil {
		return nil, fmt.Errorf("metering/sqlite: active_users: %w", err)
	}

	// MFAChallenges: mfa_required events for this tenant.
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND type='mfa_required' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		tenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.MFAChallenges); err != nil {
		return nil, fmt.Errorf("metering/sqlite: mfa_challenges: %w", err)
	}

	return u, nil
}

// TopTenants returns usage for the N tenants with the most logins in the
// given period. limit is capped at 1000.
func (a *Aggregator) TopTenants(ctx context.Context, period metering.UsagePeriod, start time.Time, limit int) ([]*metering.TenantUsage, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 1000 {
		limit = 1000
	}
	since, until := periodBounds(start, period)

	tops, err := a.topTenantsByLogins(ctx, period, since, until, limit)
	if err != nil {
		return nil, err
	}
	for _, u := range tops {
		if err := a.fillTenantMetrics(ctx, u, since, until); err != nil {
			return nil, err
		}
	}
	return tops, nil
}

// topTenantsByLogins runs the GROUP BY login aggregation and returns the
// tenants ordered by login count (preserving the SQL ORDER BY ... DESC LIMIT
// ranking), seeded with Period/PeriodStart and the login total only.
func (a *Aggregator) topTenantsByLogins(ctx context.Context, period metering.UsagePeriod, since, until time.Time, limit int) ([]*metering.TenantUsage, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT tenant_id, COUNT(*) as logins FROM audit_events WHERE type='login' AND outcome='success' AND tenant_id!='' AND ts_unix_ns>=? AND ts_unix_ns<? GROUP BY tenant_id ORDER BY logins DESC LIMIT ?`,
		since.UnixNano(), until.UnixNano(), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("metering/sqlite: top_tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tops []*metering.TenantUsage
	for rows.Next() {
		u := &metering.TenantUsage{Period: period, PeriodStart: since}
		if err := rows.Scan(&u.TenantID, &u.Logins); err != nil {
			return nil, fmt.Errorf("metering/sqlite: top_tenants scan: %w", err)
		}
		tops = append(tops, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("metering/sqlite: top_tenants rows: %w", err)
	}
	return tops, nil
}

// fillTenantMetrics fetches the non-login metrics for one tenant over the
// [since, until) window. We accept N round-trips (one per tenant) because
// TopTenants is an operator dashboard call, not a hot-path per-request
// operation, and the limit keeps N small.
func (a *Aggregator) fillTenantMetrics(ctx context.Context, u *metering.TenantUsage, since, until time.Time) error {
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND type='token_issued' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		u.TenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.TokensIssued); err != nil {
		return fmt.Errorf("metering/sqlite: top_tenants tokens: %w", err)
	}
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT actor_id) FROM audit_events WHERE tenant_id=? AND type='login' AND outcome='success' AND actor_id!='' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		u.TenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.ActiveUsers); err != nil {
		return fmt.Errorf("metering/sqlite: top_tenants users: %w", err)
	}
	if err := a.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_events WHERE tenant_id=? AND type='mfa_required' AND ts_unix_ns>=? AND ts_unix_ns<?`,
		u.TenantID, since.UnixNano(), until.UnixNano(),
	).Scan(&u.MFAChallenges); err != nil {
		return fmt.Errorf("metering/sqlite: top_tenants mfa: %w", err)
	}
	return nil
}

// periodBounds returns the [since, until) UTC half-open interval for the
// period containing t.
func periodBounds(t time.Time, period metering.UsagePeriod) (since, until time.Time) {
	t = t.UTC()
	if period == metering.PeriodMonth {
		since = time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		until = since.AddDate(0, 1, 0)
		return
	}
	since = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	until = since.AddDate(0, 0, 1)
	return
}

var _ metering.Aggregator = (*Aggregator)(nil)
