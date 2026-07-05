package admingovernance

import (
	"context"
	"time"
)

// QuotaResult is the outcome of one WriteQuotaStore.Consume call.
type QuotaResult struct {
	// Allowed is false when the increment would exceed (or already
	// exhausted) the configured limit for the current window.
	Allowed bool
	// Remaining is the number of writes still available in the current
	// window (0 when Allowed is false).
	Remaining int
	// ResetAt is when the current fixed window closes and the budget
	// resets to Limit — the "resets on a schedule" behavior that
	// distinguishes a QUOTA from a token-bucket rate limiter (which has no
	// notion of a reset time, only a refill rate).
	ResetAt time.Time
}

// WriteQuotaStore enforces a hard, fixed-window budget on the number of
// admin WRITE operations a key (a tenant or an admin identity — see
// QuotaKey) may perform per window. Distinct from a token-bucket rate
// limiter: a quota is a bounded ALLOWANCE that resets wholesale at fixed
// window boundaries, not a continuously-refilling rate.
type WriteQuotaStore interface {
	// Consume attempts to charge one write against key's budget for the
	// window containing now. limit <= 0 or window <= 0 means "unlimited"
	// (implementations MUST return Allowed=true without bookkeeping).
	Consume(ctx context.Context, key string, limit int, window time.Duration, now time.Time) (QuotaResult, error)
}

// QuotaKey derives the WriteQuotaStore key for one request. keyBy selects
// the dimension the operator wants the hard budget tracked against:
//
//   - "tenant": keyed by tenantHint (the acting admin's tenant, when the
//     validated bearer carries one) — every admin acting for that tenant
//     shares one budget. Falls back to admin identity when no tenant hint
//     is available on the token (e.g. a global admin token).
//   - anything else (including "", the default "admin"): keyed by the
//     acting admin's own identity — each admin has an independent budget.
func QuotaKey(keyBy, actorID, tenantHint string) string {
	if keyBy == "tenant" && tenantHint != "" {
		return "tenant:" + tenantHint
	}
	return "admin:" + actorID
}
