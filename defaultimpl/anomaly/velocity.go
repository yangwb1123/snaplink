package anomaly

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
)

// DetectorTypeVelocity is the wire-stable [sso.Anomaly.Type]
// surfaced by [VelocityDetector]. Used in SIEM rules + metric
// labels; renaming silently breaks operator dashboards.
const DetectorTypeVelocity = "velocity_burst"

// VelocityDetector flags subjects whose login attempt rate in a
// sliding window exceeds operator-configured thresholds. Catches:
//
//   - Credential stuffing on a small list of high-value accounts
//     (attacker tries the same login 100x/hour from automation).
//   - Compromised credentials being replayed by an attacker bot
//     (success burst on an account that normally sees 1 login/day).
//
// The detector consults the same [sso.RecentLoginStore] as the
// impossible-travel detector — both read history; impossible-travel
// writes; velocity is read-only. (Centralizing writes in
// impossible-travel keeps the SPI flat and matches the
// "writes too" invariant documented there.)
//
// Two configurable thresholds:
//
//   - HourlyLimit: attempts in the last hour > N → warn anomaly.
//     Default 25.
//   - DailyLimit:  attempts in the last 24h > N → critical anomaly.
//     Default 200.
//
// Both thresholds checked independently; a subject crossing both
// produces two anomalies (operators want both signals — the daily
// one is the "this isn't a transient burst" indicator).
//
// Counts include BOTH success + failure (matches RecentLoginStore
// semantics). A failure-only velocity check would miss the worst
// case: an attacker who has the right credentials and is now
// hammering with successful logins to mass-exfiltrate before the
// account is locked.
type VelocityDetector struct {
	store       sso.RecentLoginStore
	hourlyLimit int
	dailyLimit  int
	// readLimit bounds the store query to prevent runaway scans
	// on subjects with thousands of entries. >dailyLimit by 2x so
	// the count is reliable even past threshold.
	readLimit int
}

// VelocityOption tunes the detector at construction.
type VelocityOption func(*VelocityDetector)

// WithVelocityHourlyLimit overrides the default 25/hour warn
// threshold. 0 disables the hourly check entirely (only daily fires).
func WithVelocityHourlyLimit(n int) VelocityOption {
	return func(d *VelocityDetector) {
		if n >= 0 {
			d.hourlyLimit = n
		}
	}
}

// WithVelocityDailyLimit overrides the default 200/day critical
// threshold. 0 disables the daily check entirely.
func WithVelocityDailyLimit(n int) VelocityOption {
	return func(d *VelocityDetector) {
		if n >= 0 {
			d.dailyLimit = n
		}
	}
}

// NewVelocityDetector builds a detector against the given store.
// Store nil → error (no history = no signal). Both limit knobs
// default — operators tune per-deployment based on traffic
// baseline.
func NewVelocityDetector(store sso.RecentLoginStore, opts ...VelocityOption) (*VelocityDetector, error) {
	if store == nil {
		return nil, errors.New("anomaly/velocity: store required")
	}
	d := &VelocityDetector{
		store:       store,
		hourlyLimit: 25,
		dailyLimit:  200,
	}
	for _, opt := range opts {
		opt(d)
	}
	// Read-limit covers the larger threshold + 2x headroom so the
	// count comparison is reliable when the subject crosses the
	// threshold (we need to know it's >= N+1, not just >= readLimit).
	d.readLimit = max(d.dailyLimit*2, 100)
	return d, nil
}

// Name returns the stable detector identifier.
func (d *VelocityDetector) Name() string { return DetectorTypeVelocity }

// Inspect counts the subject's recent attempts within the last
// hour + last 24h, surfaces anomalies when either threshold is
// breached. Pure read — does NOT append (impossible-travel owns
// the writes).
func (d *VelocityDetector) Inspect(ctx context.Context, event *sso.LoginEvent) ([]sso.Anomaly, error) {
	if event == nil || event.SubjectID == "" {
		return nil, nil
	}
	// Earliest cutoff = whichever window is in play.
	dayCutoff := event.Timestamp.Add(-24 * time.Hour)
	entries, err := d.store.Recent(ctx, event.SubjectID, dayCutoff, d.readLimit)
	if err != nil {
		return nil, fmt.Errorf("anomaly/velocity: lookup: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}

	hourCutoff := event.Timestamp.Add(-1 * time.Hour)
	var hourlyCount, dailyCount int
	for _, e := range entries {
		dailyCount++ // already filtered by dayCutoff in the query
		if !e.Timestamp.Before(hourCutoff) {
			hourlyCount++
		}
	}
	// Add 1 for the current event itself — not yet in the store
	// (impossible-travel appends after Inspect; without that, this
	// would be off-by-one on the very first cross-threshold call).
	hourlyCount++
	dailyCount++

	var anomalies []sso.Anomaly
	if d.hourlyLimit > 0 && hourlyCount > d.hourlyLimit {
		anomalies = append(anomalies, sso.Anomaly{
			Type:      DetectorTypeVelocity,
			Severity:  sso.AnomalySeverityWarn,
			Score:     velocityScore(hourlyCount, d.hourlyLimit),
			SubjectID: event.SubjectID,
			Evidence: map[string]string{
				"window":         "1h",
				"count":          formatInt(int64(hourlyCount)),
				"threshold":      formatInt(int64(d.hourlyLimit)),
				"current_client": event.ClientID,
			},
		})
	}
	if d.dailyLimit > 0 && dailyCount > d.dailyLimit {
		anomalies = append(anomalies, sso.Anomaly{
			Type:      DetectorTypeVelocity,
			Severity:  sso.AnomalySeverityCritical,
			Score:     velocityScore(dailyCount, d.dailyLimit),
			SubjectID: event.SubjectID,
			Evidence: map[string]string{
				"window":         "24h",
				"count":          formatInt(int64(dailyCount)),
				"threshold":      formatInt(int64(d.dailyLimit)),
				"current_client": event.ClientID,
			},
		})
	}
	return anomalies, nil
}

// velocityScore maps (count, threshold) to 0..100. Caps at 100
// when count >= 5x threshold (the signal saturates — operators
// don't need finer resolution past that).
func velocityScore(count, threshold int) int {
	if threshold <= 0 {
		return 0
	}
	ratio := float64(count) / float64(threshold)
	if ratio >= 5 {
		return 100
	}
	// 1.0 → 50, 2.0 → 70, 3.0 → 80, 5.0 → 100.
	score := int(50 + (ratio-1)*12.5)
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

var _ sso.AnomalyDetector = (*VelocityDetector)(nil)
