package anomaly

import (
	"context"
	"time"
)

// IPFailureCounter tracks login failures keyed by SOURCE IP (not
// subject) so the [BruteForceShadowDetector] can catch attackers
// spraying attempts across N accounts to stay below per-account
// lockout — the failure mode AccountLockout can't see by design.
//
// Wire shape mirrors [RecentLoginStore]: Record (write) + Query
// (read) + PruneOlder (retention). Storage is intentionally
// minimal — counter aggregations, not full event rows — so the
// schema can scale to high-traffic deploys without bloating to
// recent_logins size.
//
// Why separate from RecentLoginStore:
//
//   - Different access pattern: RecentLoginStore is subject-keyed
//     with range scans by time; IPFailureCounter is IP-keyed with
//     count + distinct-subject aggregation. A single schema
//     supporting both would need two index sets and double the
//     write cost; the operator pays for what each detector uses.
//
//   - Different retention: failure counters can be aggressive
//     (1-2h window is enough for brute-force detection); login
//     history needs 30-90 days for new-device + new-country.
//
//   - Optional independently: operators may want brute-force-only
//     (no per-subject history needed) or new-device-only (no IP
//     counter needed). Splitting lets either go unwired.
type IPFailureCounter interface {
	// Record persists one failed login attempt for
	// (tenantID, ipHash, subjectID). Empty ipHash → no-op
	// (anonymous-IP failures can't be aggregated). Empty subjectID
	// is permitted (failed authn before user resolution); the
	// counter still bumps for ipHash, just without contributing to
	// the distinct-subject count. Empty tenantID scopes to the
	// tenant-less partition.
	Record(ctx context.Context, tenantID, ipHash, subjectID string, ts time.Time) error

	// Count returns (total failures, distinct subjects) for ipHash
	// within tenantID across attempts newer than `since`. Both
	// signals matter: total = "how loud is this IP"; distinct =
	// "is this targeted at one user or a sprayed list?"
	Count(ctx context.Context, tenantID, ipHash string, since time.Time) (total int, distinct int, err error)

	// PruneOlder removes entries older than cutoff. Mirrors
	// RecentLoginStore.PruneOlder; operator wires from a retention
	// scheduler.
	PruneOlder(ctx context.Context, cutoff time.Time) (int64, error)
}
