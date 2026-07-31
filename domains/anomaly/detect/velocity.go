package detect

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
)

// VelocityConfig controls the velocity detection thresholds.
type VelocityConfig struct {
	ShortWindow        time.Duration
	ShortWindowLimit   int
	LongWindow         time.Duration
	LongWindowLimit    int
	CriticalMultiplier int
}

// DefaultVelocityConfig provides conservative defaults.
var DefaultVelocityConfig = VelocityConfig{
	ShortWindow:        5 * time.Minute,
	ShortWindowLimit:   5,
	LongWindow:         60 * time.Minute,
	LongWindowLimit:    20,
	CriticalMultiplier: 3,
}

// VelocityDetector detects rapid successive login activity for the same
// subject within configurable windows.
type VelocityDetector struct {
	loginStore anomaly.RecentLoginStore
	config     VelocityConfig
}

func NewVelocityDetector(store anomaly.RecentLoginStore, config VelocityConfig) *VelocityDetector {
	if config.ShortWindow == 0 {
		config = DefaultVelocityConfig
	}
	return &VelocityDetector{loginStore: store, config: config}
}

func (d *VelocityDetector) Name() string { return "velocity" }

func (d *VelocityDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event.SubjectID == "" {
		return nil, nil
	}

	shortCount, err := d.countInWindow(ctx, event.SubjectID, event.Timestamp, d.config.ShortWindow)
	if err != nil {
		return nil, err
	}
	longCount, err := d.countInWindow(ctx, event.SubjectID, event.Timestamp, d.config.LongWindow)
	if err != nil {
		return nil, err
	}
	if shortCount < d.config.ShortWindowLimit && longCount < d.config.LongWindowLimit {
		return nil, nil
	}

	sig := d.buildSignal(shortCount, longCount, event.SubjectID)
	return []anomaly.Signal{sig}, nil
}

func (d *VelocityDetector) countInWindow(ctx context.Context, subjectID string, now time.Time, window time.Duration) (int, error) {
	since := now.Add(-window)
	entries, err := d.loginStore.Recent(ctx, subjectID, since, 0)
	if err != nil {
		return 0, err
	}
	return len(entries), nil
}

func (d *VelocityDetector) buildSignal(shortCount, longCount int, subjectID string) anomaly.Signal {
	st := d.config.ShortWindowLimit
	lt := d.config.LongWindowLimit
	cs := st * d.config.CriticalMultiplier
	cl := lt * d.config.CriticalMultiplier

	severity := anomaly.SeverityWarn
	if shortCount >= cs || longCount >= cl {
		severity = anomaly.SeverityCritical
	}

	evidence := map[string]string{
		"short_window":        d.config.ShortWindow.String(),
		"short_window_count":  itoa(shortCount),
		"short_window_limit":  itoa(st),
		"long_window":         d.config.LongWindow.String(),
		"long_window_count":   itoa(longCount),
		"long_window_limit":   itoa(lt),
		"critical_multiplier": itoa(d.config.CriticalMultiplier),
	}

	return anomaly.Signal{
		Type:      "velocity_burst",
		Severity:  severity,
		Score:     velocityScore(shortCount, longCount, cs, cl),
		Evidence:  evidence,
		SubjectID: subjectID,
	}
}

func velocityScore(shortCount, longCount, cs, cl int) int {
	var score int
	if cs > 0 {
		if s := (shortCount * 100) / cs; s > score {
			score = s
		}
	}
	if cl > 0 {
		if s := (longCount * 100) / cl; s > score {
			score = s
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}
