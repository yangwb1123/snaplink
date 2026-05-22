package anomaly

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
)

// DetectorTypeBruteForceShadow is the wire-stable [sso.Anomaly.Type]
// for the brute-force shadow detector.
const DetectorTypeBruteForceShadow = "brute_force_shadow"

// BruteForceShadowDetector catches the failure mode AccountLockout
// CANNOT see by design: an attacker spraying credentials across N
// accounts to stay below the per-account lockout threshold. From
// each account's perspective the IP only failed 4 times (under
// the typical 5-fail lockout); from the IP's perspective it's
// hammered 4 × N = 400 failures across 100 accounts.
//
// Reads + writes to a separate [sso.IPFailureCounter] — the schema
// is IP-keyed (not subject-keyed) so the count + distinct-subjects
// aggregation is one indexed query.
//
// Two thresholds, both must be configurable per-deployment:
//
//   - FailureLimit: total failures from one IP in window > N → warn.
//     Default 50 (a real user mistyping 5x is normal; 50x in 1h is
//     not).
//   - DistinctSubjectLimit: distinct subjects targeted from one IP
//     in window > N → critical. Default 10 (legitimate
//     shared-IP scenarios — SOHO NATs, corporate proxies — have
//     few users; spray attacks have dozens).
//
// Both thresholds checked independently; an IP crossing both
// produces two anomalies (operators want both signals).
//
// Only writes on FAILURE events. Success events don't increment
// the counter — the counter is "how loud is this IP being wrong?"
// not "how loud is this IP overall."
type BruteForceShadowDetector struct {
	counter              sso.IPFailureCounter
	ipSalt               []byte
	window               time.Duration
	failureLimit         int
	distinctSubjectLimit int
}

// BruteForceShadowOption tunes the detector at construction.
type BruteForceShadowOption func(*BruteForceShadowDetector)

// WithBruteForceShadowWindow overrides the default 1-hour window.
// Wider = more historical context but slower to fire; narrower =
// faster signal at the cost of slow-burn missed.
func WithBruteForceShadowWindow(d time.Duration) BruteForceShadowOption {
	return func(det *BruteForceShadowDetector) {
		if d > 0 {
			det.window = d
		}
	}
}

// WithBruteForceShadowFailureLimit overrides the default 50/window
// failure threshold. 0 disables this check (only distinct-subject
// fires).
func WithBruteForceShadowFailureLimit(n int) BruteForceShadowOption {
	return func(det *BruteForceShadowDetector) {
		if n >= 0 {
			det.failureLimit = n
		}
	}
}

// WithBruteForceShadowDistinctSubjectLimit overrides the default
// 10/window distinct-subject threshold. 0 disables this check.
func WithBruteForceShadowDistinctSubjectLimit(n int) BruteForceShadowOption {
	return func(det *BruteForceShadowDetector) {
		if n >= 0 {
			det.distinctSubjectLimit = n
		}
	}
}

// NewBruteForceShadowDetector builds a detector against the given
// counter. counter nil → error. ipSalt is the same deployment salt
// used by HashLoginEntry so the IP hash schema matches across
// detectors.
func NewBruteForceShadowDetector(counter sso.IPFailureCounter, ipSalt []byte, opts ...BruteForceShadowOption) (*BruteForceShadowDetector, error) {
	if counter == nil {
		return nil, errors.New("anomaly/brute_force_shadow: counter required")
	}
	d := &BruteForceShadowDetector{
		counter:              counter,
		ipSalt:               append([]byte(nil), ipSalt...),
		window:               1 * time.Hour,
		failureLimit:         50,
		distinctSubjectLimit: 10,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// Name returns the stable detector identifier.
func (d *BruteForceShadowDetector) Name() string { return DetectorTypeBruteForceShadow }

// Inspect records this failure (if it IS a failure) + checks both
// thresholds against the IP's total count + distinct-subjects
// count in the window.
func (d *BruteForceShadowDetector) Inspect(ctx context.Context, event *sso.LoginEvent) ([]sso.Anomaly, error) {
	if event == nil || event.RemoteIP == "" {
		return nil, nil
	}
	ipHash := hashIPForBF(event.RemoteIP, d.ipSalt)
	if ipHash == "" {
		return nil, nil
	}
	if event.Outcome == "failure" {
		if err := d.counter.Record(ctx, ipHash, event.SubjectID, event.Timestamp); err != nil {
			return nil, fmt.Errorf("anomaly/brute_force_shadow: record: %w", err)
		}
	}
	// Even on success, check whether this IP has been hammering
	// other accounts — a successful login from a suspicious IP is
	// itself a signal (attacker found a valid credential).
	since := event.Timestamp.Add(-d.window)
	total, distinct, err := d.counter.Count(ctx, ipHash, since)
	if err != nil {
		return nil, fmt.Errorf("anomaly/brute_force_shadow: count: %w", err)
	}

	var anomalies []sso.Anomaly
	if d.failureLimit > 0 && total > d.failureLimit {
		anomalies = append(anomalies, sso.Anomaly{
			Type:      DetectorTypeBruteForceShadow,
			Severity:  sso.AnomalySeverityWarn,
			Score:     bfScore(total, d.failureLimit),
			SubjectID: event.SubjectID,
			Evidence: map[string]string{
				"window":            d.window.String(),
				"total_failures":    formatInt(int64(total)),
				"distinct_subjects": formatInt(int64(distinct)),
				"failure_threshold": formatInt(int64(d.failureLimit)),
				"current_outcome":   event.Outcome,
			},
		})
	}
	if d.distinctSubjectLimit > 0 && distinct > d.distinctSubjectLimit {
		anomalies = append(anomalies, sso.Anomaly{
			Type:      DetectorTypeBruteForceShadow,
			Severity:  sso.AnomalySeverityCritical,
			Score:     bfScore(distinct, d.distinctSubjectLimit),
			SubjectID: event.SubjectID,
			Evidence: map[string]string{
				"window":                     d.window.String(),
				"total_failures":             formatInt(int64(total)),
				"distinct_subjects":          formatInt(int64(distinct)),
				"distinct_subject_threshold": formatInt(int64(d.distinctSubjectLimit)),
				"current_outcome":            event.Outcome,
			},
		})
	}
	return anomalies, nil
}

// hashIPForBF reuses the same salted SHA-256 truncation scheme as
// defaultimpl.HashLoginEntry so the IP hash space is consistent
// across detectors. Inlined here to keep this subpackage from
// depending on defaultimpl beyond the public hashing contract
// (16 hex chars = 64-bit truncation of sha256(salt || ip)).
func hashIPForBF(ip string, salt []byte) string {
	if ip == "" {
		return ""
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(ip))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// bfScore maps (count, threshold) → 0..100 with saturation. Same
// shape as VelocityDetector's score.
func bfScore(count, threshold int) int {
	if threshold <= 0 {
		return 0
	}
	ratio := float64(count) / float64(threshold)
	if ratio >= 5 {
		return 100
	}
	score := int(50 + (ratio-1)*12.5)
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

var _ sso.AnomalyDetector = (*BruteForceShadowDetector)(nil)
