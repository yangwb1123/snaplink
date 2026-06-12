// Package memory is an in-memory [metering.Aggregator] for tests.
// Pre-populate it with Record; Usage and TopTenants scan the slice.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/snaplink/sso/metering"
)

// Aggregator is the in-memory implementation of [metering.Aggregator].
// Safe for concurrent use.
type Aggregator struct {
	mu      sync.RWMutex
	records []*metering.TenantUsage
}

// New returns an empty Aggregator.
func New() *Aggregator { return &Aggregator{} }

// Record adds a pre-computed TenantUsage entry. Use in tests to
// pre-populate the aggregator without a real audit log.
func (a *Aggregator) Record(u *metering.TenantUsage) {
	if u == nil {
		return
	}
	a.mu.Lock()
	a.records = append(a.records, u)
	a.mu.Unlock()
}

// Usage returns the first stored record whose TenantID, Period, and
// PeriodStart (truncated to period) match, or a zero-count record when
// none is found. The caller owns the returned pointer.
func (a *Aggregator) Usage(_ context.Context, tenantID string, period metering.UsagePeriod, start time.Time) (*metering.TenantUsage, error) {
	start = truncate(start, period)
	a.mu.RLock()
	defer a.mu.RUnlock()
	for _, r := range a.records {
		if r.TenantID == tenantID && r.Period == period && truncate(r.PeriodStart, period).Equal(start) {
			cp := *r
			return &cp, nil
		}
	}
	return &metering.TenantUsage{
		TenantID:    tenantID,
		Period:      period,
		PeriodStart: start,
	}, nil
}

// TopTenants returns up to limit records from the store sorted descending
// by Logins. When multiple records share (Period, PeriodStart) only the
// first matching record per TenantID is considered.
func (a *Aggregator) TopTenants(_ context.Context, period metering.UsagePeriod, start time.Time, limit int) ([]*metering.TenantUsage, error) {
	if limit <= 0 {
		limit = 10
	}
	start = truncate(start, period)
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Deduplicate by tenant: keep the first record per tenant for this
	// period/start, since Record() can be called multiple times.
	seen := make(map[string]*metering.TenantUsage)
	for _, r := range a.records {
		if r.Period != period || !truncate(r.PeriodStart, period).Equal(start) {
			continue
		}
		if _, ok := seen[r.TenantID]; !ok {
			cp := *r
			seen[r.TenantID] = &cp
		}
	}
	out := make([]*metering.TenantUsage, 0, len(seen))
	for _, v := range seen {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Logins > out[j].Logins })
	if limit > len(out) {
		limit = len(out)
	}
	return out[:limit], nil
}

// truncate normalises start to the UTC period boundary so callers with
// slightly-off timestamps still hit the right bucket.
func truncate(t time.Time, period metering.UsagePeriod) time.Time {
	t = t.UTC()
	if period == metering.PeriodMonth {
		return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

var _ metering.Aggregator = (*Aggregator)(nil)
