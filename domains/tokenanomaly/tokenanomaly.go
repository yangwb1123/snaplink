// Package tokenanomaly is the token-behavior anomaly detection subsystem —
// Phase 3 of token governance, layered on the wave-1 domains/tokenusage
// telemetry.
//
// It runs OFF the request hot path, mirroring domains/anomaly: the wave-1
// [tokenusage.Recorder] drains usage Events into a [Detector] (a
// tokenusage.Store decorator) on a background goroutine, and a periodic
// [Detector.Analyze] sweep inspects the accumulated per-thumbprint
// observations plus the aggregated usage buckets and emits [Finding]s. It is
// DETECTION / REPORTING ONLY — a Finding NEVER feeds an authentication or
// authorization decision (the same hard contract as anomaly.Detector). Every
// Finding surfaces through the admin "suspicious tokens" read API plus a
// bounded metric; nothing on the request path ever reads the finding store.
//
// Detection is pattern-based rather than fixed-threshold:
//
//   - multi_geo  — one token thumbprint observed from >= 2 distinct coarse
//     geos within the analysis window (a bearer token is not supposed to
//     roam countries). Distinct-geo CARDINALITY is the signal, not a tunable
//     rate.
//   - velocity   — the same, but the two distinct-geo sightings happened
//     within VelocityGap of each other: physically impossible travel for a
//     single credential, so a stronger (critical) signal.
//   - rate_spike — a client's most-recent-minute issuance count exceeds its
//     OWN trailing baseline by SpikeFactor (an adaptive, per-client multiple),
//     gated by a small absolute floor so tiny volumes don't trip it.
//
// Privacy (consistent with tokenusage.Event): a Finding carries only the
// token thumbprint (the wave-1 SHA-256(jti), NEVER the token value), a coarse
// ISO-3166 geo set, the owning client id, and the subject id — the single
// PII field. It never carries a token value, a full IP, or finer-grained geo.
package tokenanomaly

import (
	"context"
	"time"
)

// Severity ranks a finding for downstream routing. Bounded set — it is a
// metric label. Only warn/critical exist: a token-behavior finding is by
// construction "worth a look", so there is no info tier (unlike the login
// anomaly subsystem, which has benign informational signals).
type Severity string

const (
	// SeverityWarn is the default: an unusual pattern an operator should
	// review (e.g. a token seen from two countries over an hour).
	SeverityWarn Severity = "warn"
	// SeverityCritical is a high-confidence abuse pattern (impossible
	// travel, or a token spread across three or more countries).
	SeverityCritical Severity = "critical"
)

// Finding type identifiers. Bounded, stable wire strings — used as a metric
// label, so this set must stay small.
const (
	// FindingMultiGeo marks a token thumbprint observed from multiple
	// distinct coarse geos within the analysis window.
	FindingMultiGeo = "multi_geo"
	// FindingVelocity marks impossible travel: two distinct-geo sightings of
	// one thumbprint closer together than the velocity gap.
	FindingVelocity = "velocity"
	// FindingRateSpike marks a client whose latest-minute issuance rate broke
	// well above its own trailing baseline.
	FindingRateSpike = "rate_spike"
)

// Finding is one detected anomaly. It is governance/reporting data only: it
// carries a token thumbprint (never a token value), the owning client, the
// subject, and a coarse geo set. Marshaled directly onto the admin
// "suspicious tokens" read API.
type Finding struct {
	// Type is one of the Finding* constants (bounded).
	Type string `json:"type"`
	// Severity ranks the finding (bounded).
	Severity Severity `json:"severity"`
	// Thumbprint is the wave-1 SHA-256(jti) of the token the finding concerns.
	// Empty for a client-scoped finding (rate_spike, which is per-client, not
	// per-token).
	Thumbprint string `json:"token_thumbprint,omitempty"`
	// ClientID is the client that owns the token / drove the spike.
	ClientID string `json:"client_id,omitempty"`
	// SubjectID is the subject the token was issued to. The single PII field;
	// omitted when unknown (e.g. rate_spike, or introspection of a token whose
	// sub was absent).
	SubjectID string `json:"subject_id,omitempty"`
	// Geos is the sorted set of coarse ISO-3166 geos the token was observed
	// from (geo/velocity findings only).
	Geos []string `json:"geos,omitempty"`
	// Detail is a short human-readable rationale (never a secret) — e.g. the
	// implied travel interval or the spike multiple.
	Detail string `json:"detail,omitempty"`
	// Count is the number of usages behind the finding (sightings for a
	// per-token finding, latest-minute count for a spike).
	Count int64 `json:"count,omitempty"`
	// FirstSeen / LastSeen bound the observation window that produced the
	// finding.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DedupKey is the identity a [FindingStore] upserts on: the same anomaly
// re-detected on a later sweep updates the existing row (LastSeen, Count,
// Geos, escalated Severity) rather than appending a duplicate. Per-token
// findings key on (type, thumbprint); the per-client rate_spike keys on
// (type, client).
func (f Finding) DedupKey() string {
	id := f.Thumbprint
	if id == "" {
		id = f.ClientID
	}
	return f.Type + "\x00" + id
}

// FindingQuery filters a [FindingStore.List]. Zero-value fields are
// unbounded; Limit <= 0 returns every match.
type FindingQuery struct {
	// Type restricts to one finding type (empty = all).
	Type string
	// Severity restricts to one severity (empty = all).
	Severity Severity
	// Limit caps the returned rows (<= 0 = no cap). Results are ordered
	// most-recent LastSeen first, so a limit keeps the freshest findings.
	Limit int
}

// FindingStore persists detected anomalies for the admin read API. Add is
// an UPSERT keyed by [Finding.DedupKey] — a repeatedly-detected anomaly must
// not accumulate duplicate rows (the store is a bounded operational view, not
// an audit log; the audit trail is the auditor's job). Implementations MUST
// be safe for concurrent use: the Analyze sweep writes while the admin read
// API lists.
type FindingStore interface {
	Add(ctx context.Context, f Finding) error
	List(ctx context.Context, q FindingQuery) ([]Finding, error)
}
