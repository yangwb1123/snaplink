package detect

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
)

// CredentialStuffingConfig controls detection thresholds.
type CredentialStuffingConfig struct {
	Window              time.Duration
	MinTotalFailures    int
	MinDistinctSubjects int
	SevereMinTotal      int
	SevereMinDistinct   int
}

// DefaultCredentialStuffingConfig provides conservative defaults.
var DefaultCredentialStuffingConfig = CredentialStuffingConfig{
	Window:              5 * time.Minute,
	MinTotalFailures:    10,
	MinDistinctSubjects: 3,
	SevereMinTotal:      30,
	SevereMinDistinct:   10,
}

// CredentialStuffingDetector detects horizontal password spraying by
// monitoring per-IP failure counts across many user accounts.
type CredentialStuffingDetector struct {
	failCounter anomaly.IPFailureCounter
	config      CredentialStuffingConfig
}

// NewCredentialStuffingDetector creates a new detector. Zero config uses defaults.
func NewCredentialStuffingDetector(counter anomaly.IPFailureCounter, config CredentialStuffingConfig) *CredentialStuffingDetector {
	if config.Window == 0 {
		config = DefaultCredentialStuffingConfig
	}
	return &CredentialStuffingDetector{
		failCounter: counter,
		config:      config,
	}
}

func (d *CredentialStuffingDetector) Name() string { return "credential_stuffing" }

func (d *CredentialStuffingDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event.Outcome != "failure" || event.RemoteIP == "" {
		return nil, nil
	}

	ipHash := sha256Hex(event.RemoteIP)
	since := event.Timestamp.Add(-d.config.Window)

	total, distinct, err := d.failCounter.Count(ctx, ipHash, since)
	if err != nil {
		return nil, err
	}
	if total < d.config.MinTotalFailures || distinct < d.config.MinDistinctSubjects {
		return nil, nil
	}

	severity := anomaly.SeverityWarn
	if total >= d.config.SevereMinTotal || distinct >= d.config.SevereMinDistinct {
		severity = anomaly.SeverityCritical
	}

	evidence := map[string]string{
		"window":            d.config.Window.String(),
		"total_failures":    itoa(total),
		"distinct_subjects": itoa(distinct),
		"ip_hash":           ipHash[:12],
	}

	return []anomaly.Signal{{
		Type:      "credential_stuffing",
		Severity:  severity,
		Score:     credentialScore(total, d.config.SevereMinTotal),
		Evidence:  evidence,
		SubjectID: event.SubjectID,
	}}, nil
}

func credentialScore(total, severe int) int {
	if severe <= 0 {
		severe = 30
	}
	if total <= 0 {
		return 0
	}
	score := (total * 100) / (severe * 2)
	if score > 100 {
		score = 100
	}
	return score
}
