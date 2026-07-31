package detect

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/domains/anomaly/signature"
)

// NewCountryConfig controls the new-country lookback window.
type NewCountryConfig struct {
	HistoryWindow time.Duration
}

// DefaultNewCountryConfig sets a 90-day lookback.
var DefaultNewCountryConfig = NewCountryConfig{
	HistoryWindow: 90 * 24 * time.Hour,
}

// NewCountryDetector raises an info signal when a subject logs in from
// a country not seen before.
type NewCountryDetector struct {
	store  signature.Store
	config NewCountryConfig
}

func NewNewCountryDetector(store signature.Store, config NewCountryConfig) *NewCountryDetector {
	if config.HistoryWindow == 0 {
		config = DefaultNewCountryConfig
	}
	return &NewCountryDetector{store: store, config: config}
}

func (d *NewCountryDetector) Name() string { return "new_country" }

func (d *NewCountryDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event.SubjectID == "" || event.Geo == nil || event.Geo.CountryCode == "" {
		return nil, nil
	}

	geoKey := "geo:" + event.Geo.CountryCode
	since := event.Timestamp.Add(-d.config.HistoryWindow)
	seen, err := d.store.Seen(ctx, geoKey, since, event.SubjectID)
	if err != nil {
		return nil, err
	}
	if seen {
		return nil, nil
	}

	evidence := map[string]string{"country": event.Geo.CountryCode}
	if event.Geo.Region != "" {
		evidence["region"] = event.Geo.Region
	}

	return []anomaly.Signal{{
		Type:      "new_country",
		Severity:  anomaly.SeverityInfo,
		Score:     20,
		Evidence:  evidence,
		SubjectID: event.SubjectID,
	}}, nil
}
