// Package metering provides an SPI and implementations for per-tenant
// usage aggregation. It queries the audit log to compute login counts,
// token issuances, active-user and active-client cardinality, and MFA
// challenge volume — the metrics a billing or quota system needs.
//
// Wire the SQLite aggregator when the audit/sqlite.Sink is in use:
//
//	agg, err := meteringdb.New(auditDSN)
//	sso.WithTenantUsageAggregator(agg)
//
// For tests use the memory aggregator with pre-populated records:
//
//	agg := meteringmemory.New()
//	agg.Record(&metering.TenantUsage{...})
package metering

import (
	"context"
	"time"
)

// UsagePeriod is the granularity of a usage aggregation.
type UsagePeriod string

const (
	// PeriodDay aggregates events within a single calendar day (UTC).
	PeriodDay UsagePeriod = "day"
	// PeriodMonth aggregates events within a single calendar month (UTC).
	PeriodMonth UsagePeriod = "month"
)

// TenantUsage holds aggregated usage metrics for one tenant over one
// period. All counts are non-negative; a zero count means no events of
// that type occurred in the window.
type TenantUsage struct {
	TenantID      string
	Period        UsagePeriod
	PeriodStart   time.Time
	Logins        int64 // login events with outcome=success
	TokensIssued  int64 // token_issued events
	ActiveUsers   int64 // distinct ActorIDs that logged in successfully
	MFAChallenges int64 // mfa_required events
	// ActiveClients is the distinct ClientID count for the tenant in the
	// period, computed from the audit log like ActiveUsers — NOT from the
	// tokenusage store. tokenusage buckets are deployment-wide token
	// telemetry keyed by (minute, client, kind, endpoint) and drop the
	// tenant dimension by design; the audit log already carries tenant +
	// client on every event and is metering's single source of truth for
	// the per-tenant billing view.
	ActiveClients int64
}

// Aggregator computes per-tenant usage from the audit log.
type Aggregator interface {
	// Usage returns aggregated metrics for tenantID over the period
	// starting at start. start is truncated to the period boundary
	// (UTC day or month) by the implementation.
	Usage(ctx context.Context, tenantID string, period UsagePeriod, start time.Time) (*TenantUsage, error)

	// TopTenants returns usage for the N tenants with the most logins
	// in the given period. Used for operator dashboards. limit MUST be
	// > 0; implementations clamp to a reasonable internal maximum.
	TopTenants(ctx context.Context, period UsagePeriod, start time.Time, limit int) ([]*TenantUsage, error)
}
