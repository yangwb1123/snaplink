package anomaly

import (
	"context"
	"errors"
	"time"
)

// RecentLoginStore persists a windowed per-subject history of login
// attempts — the substrate every behavioral [Detector] needs
// when it asks "what did this subject do in the last N minutes?"
//
// Designed for OFF the request hot path (the [Runner]
// consumes it). Writes are append-only; reads are bounded by
// subject + time window. Backends own retention — entries older
// than the operator's policy MAY be pruned at any time (including
// on Append, lazily on Recent reads, or via background scheduler).
//
// Shape decisions:
//
//   - PER-SUBJECT keyed (not per-IP). The detectors needing IP
//     history (brute-force shadow) use [IPFailureCounter] (R7),
//     which lives separately so the schemas can evolve
//     independently — subject history needs full event records
//     for impossible-travel + new-country; IP history needs only
//     counters.
//
//   - WRITES INCLUDE FAILURES. New-device detection wants both
//     success + failure events for the same subject so it can
//     baseline "alice usually logs in from these 3 devices" even
//     when some attempts failed. Detectors that care only about
//     successes filter on `Outcome` themselves.
//
//   - NO PII IN STORAGE. The store persists hashed IP + hashed
//     UA fingerprint, never the raw values. Hashing happens at
//     write time in [Append] — operators wiring a custom store
//     MUST preserve this; the wrapper [HashLoginEntry] is the
//     canonical helper.
//
//   - WINDOWED READ. [Recent] returns up to N most-recent entries
//     for a subject newer than `since`. Detectors specify their
//     own window (impossible-travel: last 1 entry; velocity:
//     last 24h).
type RecentLoginStore interface {
	// Append persists one LoginEntry. Entry.SubjectID MUST be
	// non-empty (anonymous failures are skipped by detectors and
	// shouldn't enter the store). Append is best-effort — backend
	// errors are logged by the detector wrapper but do not cause
	// the anomaly dispatch to fail.
	Append(ctx context.Context, entry *LoginEntry) error

	// Recent returns up to limit most-recent entries for subjectID
	// newer than since, ordered newest-first. Backends MAY return
	// fewer entries (limit + window combined); MUST NOT return
	// older entries. limit <= 0 → backend-defined cap (typically
	// 100); since.IsZero() → no lower bound.
	//
	// Empty result is NOT an error.
	Recent(ctx context.Context, subjectID string, since time.Time, limit int) ([]*LoginEntry, error)

	// PruneOlder deletes entries older than cutoff. Operators wire
	// from a retention scheduler (mirrors the audit / snapshot /
	// push retention pattern). Returns rows deleted.
	PruneOlder(ctx context.Context, cutoff time.Time) (int64, error)
}

// LoginEntry is one row of recent-login history. Field names
// mirror [LoginEvent] but with PII hashed.
type LoginEntry struct {
	SubjectID string

	// ClientID is optional — detectors usually don't filter by
	// client, but per-client baselining is a future option.
	ClientID string

	// Outcome is "success" or "failure".
	Outcome string

	// IPHash is sha256(remote_ip || salt) truncated to 16 bytes
	// hex. The salt is operator-provided at construction so
	// per-deployment IPs don't link across deployments. Detectors
	// comparing IPs across entries do bytewise equality on this.
	IPHash string

	// CountryCode is ISO-3166 alpha-2 from the [geo.GeoInfo]
	// (when geo enrichment ran). Used by impossible-travel +
	// new-country detectors. Empty when no geo provider wired.
	CountryCode string

	// Latitude + Longitude pulled from geo enrichment for
	// distance-based detectors (impossible travel). Both 0 when
	// geo provider didn't populate; detectors should skip the
	// distance check rather than treating (0,0) as the Gulf of
	// Guinea.
	Latitude  float64
	Longitude float64

	// UAFingerprintHash is sha256(ua || subject_id_salt) truncated
	// to 16 bytes hex. Per-subject salt prevents cross-user
	// correlation of devices. New-device detector compares on this.
	// Empty when no User-Agent header was present.
	UAFingerprintHash string

	// Timestamp is the original LoginEvent.Timestamp (server-
	// captured, not client-controlled).
	Timestamp time.Time
}

// ErrInvalidLoginEntry is the sentinel Append returns when SubjectID
// is empty (or other required-field violations). Detectors
// wrapping this don't treat it as fatal — anonymous events skip
// the store.
var ErrInvalidLoginEntry = errors.New("sso: invalid LoginEntry")
