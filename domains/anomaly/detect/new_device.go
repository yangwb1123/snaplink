package detect

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/domains/anomaly/fingerprint"
	"github.com/yangwb1123/snaplink/domains/anomaly/signature"
)

// NewDeviceConfig controls the new-device lookback window.
type NewDeviceConfig struct {
	HistoryWindow time.Duration
}

// DefaultNewDeviceConfig sets a 30-day lookback.
var DefaultNewDeviceConfig = NewDeviceConfig{
	HistoryWindow: 30 * 24 * time.Hour,
}

// NewDeviceDetector raises an info signal when a subject logs in from
// a device fingerprint not seen before.
type NewDeviceDetector struct {
	store  signature.Store
	config NewDeviceConfig
}

func NewNewDeviceDetector(store signature.Store, config NewDeviceConfig) *NewDeviceDetector {
	if config.HistoryWindow == 0 {
		config = DefaultNewDeviceConfig
	}
	return &NewDeviceDetector{store: store, config: config}
}

func (d *NewDeviceDetector) Name() string { return "new_device" }

func (d *NewDeviceDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event.SubjectID == "" || event.UserAgent == "" {
		return nil, nil
	}

	fp := fingerprint.Derive(&fingerprint.Input{UserAgent: event.UserAgent})
	if fp == "" {
		return nil, nil
	}

	since := event.Timestamp.Add(-d.config.HistoryWindow)
	seen, err := d.store.Seen(ctx, fp, since, event.SubjectID)
	if err != nil {
		return nil, err
	}
	if seen {
		return nil, nil
	}

	evidence := map[string]string{
		"device_fingerprint": fp[:16],
	}

	return []anomaly.Signal{{
		Type:      "new_device",
		Severity:  anomaly.SeverityInfo,
		Score:     30,
		Evidence:  evidence,
		SubjectID: event.SubjectID,
	}}, nil
}
