package detectors

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// Wire-stable detector type identifiers, aliasing the domain-owned
// constants (domains/anomaly/consts.go). Operators alert on these
// strings in SIEM rules + metric labels.
const (
	DetectorTypeNewDevice  = anomaly.SignalTypeNewDevice
	DetectorTypeNewCountry = anomaly.SignalTypeNewCountry
)

// NewDeviceDetector flags a login from a UA fingerprint the subject
// hasn't used within the configured baseline window. Catches:
//
//   - Compromised account replay from attacker's browser.
//   - First login from a stolen physical device (UA changes if the
//     attacker switches browser).
//
// Reads from [anomaly.RecentLoginStore] — no separate device store.
// The detector treats the subject's UA fingerprint history (last
// baselineWindow's worth) as "known devices." New = current
// fingerprint not in that set.
//
// Bootstrap grace period: for the first `bootstrapGracePeriod`
// after a subject first appears in the store, every login adds to
// the baseline without flagging. Avoids the cold-start flood
// where every device is "new" because there's no history yet.
//
// Skip conditions (no false positives):
//
//   - Empty UAFingerprintHash on the current event (no User-Agent
//     header → can't fingerprint; many service-to-service flows).
//   - Subject has zero history (first-ever login is by definition
//     new device, but flagging it is noise; new-device is the
//     "RELATIVE to baseline" signal).
//   - Within bootstrap grace period.
type NewDeviceDetector struct {
	store                anomaly.RecentLoginStore
	ipSalt               []byte
	baselineWindow       time.Duration
	bootstrapGracePeriod time.Duration
}

// NewDeviceOption tunes the detector at construction.
type NewDeviceOption func(*NewDeviceDetector)

// WithNewDeviceBaselineWindow overrides the default 30-day baseline
// lookback. Wider = more device tolerance (frequent travelers, IT
// rotating refresh tokens); narrower = sharper signal at the cost
// of false-positives on infrequent users.
func WithNewDeviceBaselineWindow(d time.Duration) NewDeviceOption {
	return func(det *NewDeviceDetector) {
		if d > 0 {
			det.baselineWindow = d
		}
	}
}

// WithNewDeviceBootstrapGracePeriod overrides the default 7-day
// grace period. Within this window after a subject's first login,
// every event adds to baseline without flagging. 0 disables the
// grace period (every login outside the baseline window flags —
// usually too noisy).
func WithNewDeviceBootstrapGracePeriod(d time.Duration) NewDeviceOption {
	return func(det *NewDeviceDetector) {
		if d >= 0 {
			det.bootstrapGracePeriod = d
		}
	}
}

// NewNewDeviceDetector builds a detector against the given store.
// store nil → error. ipSalt is the deployment-stable secret used
// by the UA hashing helper (same value passed to
// impossible-travel + the AnomalyRunner stamper).
func NewNewDeviceDetector(store anomaly.RecentLoginStore, ipSalt []byte, opts ...NewDeviceOption) (*NewDeviceDetector, error) {
	if store == nil {
		return nil, errors.New("anomaly/new_device: store required")
	}
	d := &NewDeviceDetector{
		store:                store,
		ipSalt:               append([]byte(nil), ipSalt...),
		baselineWindow:       30 * 24 * time.Hour,
		bootstrapGracePeriod: 7 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// Name returns the stable detector identifier.
func (d *NewDeviceDetector) Name() string { return DetectorTypeNewDevice }

// Inspect compares the current event's UA fingerprint to the
// subject's last baselineWindow of entries.
func (d *NewDeviceDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event == nil || event.SubjectID == "" || event.UserAgent == "" {
		return nil, nil
	}
	currentHash := computeUAHash(event, d.ipSalt)
	if currentHash == "" {
		return nil, nil
	}
	since := event.Timestamp.Add(-d.baselineWindow)
	entries, err := d.store.Recent(ctx, event.TenantID, event.SubjectID, since, 0)
	if err != nil {
		return nil, fmt.Errorf("anomaly/new_device: lookup: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil // first login for subject = baseline, not signal
	}
	if d.bootstrapGracePeriod > 0 {
		oldest := entries[len(entries)-1].Timestamp
		if event.Timestamp.Sub(oldest) < d.bootstrapGracePeriod {
			return nil, nil
		}
	}
	for _, e := range entries {
		if e.UAFingerprintHash == currentHash {
			return nil, nil // known device
		}
	}
	return []anomaly.Signal{{
		Type:      DetectorTypeNewDevice,
		Severity:  anomaly.SeverityWarn,
		Score:     50,
		SubjectID: event.SubjectID,
		Evidence: map[string]string{
			"baseline_window":  d.baselineWindow.String(),
			"baseline_entries": formatInt(int64(len(entries))),
		},
	}}, nil
}

// NewCountryDetector flags a login from a country the subject
// hasn't used within the baseline window. Cheaper false-positive
// profile than new-device (countries change less than browsers /
// phones); useful when geo-only data is available without lat/lon
// (impossible-travel can't run but new-country can).
//
// Same bootstrap grace period semantics as new-device.
type NewCountryDetector struct {
	store                anomaly.RecentLoginStore
	baselineWindow       time.Duration
	bootstrapGracePeriod time.Duration
}

// NewCountryOption tunes the detector at construction.
type NewCountryOption func(*NewCountryDetector)

// WithNewCountryBaselineWindow overrides the default 90-day window.
// Wider than new-device — countries genuinely don't change often
// for the typical user; flagging a real country change once a year
// is acceptable, flagging a real device change once a year is
// suspicious only in proportion.
func WithNewCountryBaselineWindow(d time.Duration) NewCountryOption {
	return func(det *NewCountryDetector) {
		if d > 0 {
			det.baselineWindow = d
		}
	}
}

// WithNewCountryBootstrapGracePeriod overrides the default 7-day
// grace period.
func WithNewCountryBootstrapGracePeriod(d time.Duration) NewCountryOption {
	return func(det *NewCountryDetector) {
		if d >= 0 {
			det.bootstrapGracePeriod = d
		}
	}
}

// NewNewCountryDetector builds a detector against the given store.
func NewNewCountryDetector(store anomaly.RecentLoginStore, opts ...NewCountryOption) (*NewCountryDetector, error) {
	if store == nil {
		return nil, errors.New("anomaly/new_country: store required")
	}
	d := &NewCountryDetector{
		store:                store,
		baselineWindow:       90 * 24 * time.Hour,
		bootstrapGracePeriod: 7 * 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// Name returns the stable detector identifier.
func (d *NewCountryDetector) Name() string { return DetectorTypeNewCountry }

// Inspect compares the current event's country to the subject's
// baseline country set.
func (d *NewCountryDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event == nil || event.SubjectID == "" || event.Geo == nil || event.Geo.CountryCode == "" {
		return nil, nil
	}
	since := event.Timestamp.Add(-d.baselineWindow)
	entries, err := d.store.Recent(ctx, event.TenantID, event.SubjectID, since, 0)
	if err != nil {
		return nil, fmt.Errorf("anomaly/new_country: lookup: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil // first login = baseline
	}
	if d.withinGracePeriod(event, entries) {
		return nil, nil
	}
	current := event.Geo.CountryCode
	for _, e := range entries {
		if e.CountryCode == current {
			return nil, nil // known country
		}
	}
	return []anomaly.Signal{{
		Type:      DetectorTypeNewCountry,
		Severity:  anomaly.SeverityWarn,
		Score:     50,
		SubjectID: event.SubjectID,
		Evidence: map[string]string{
			"current_country":    current,
			"baseline_countries": baselineCountryList(entries),
			"baseline_entries":   formatInt(int64(len(entries))),
		},
	}}, nil
}

// withinGracePeriod reports whether the subject's oldest baseline
// entry is recent enough that the bootstrap grace period still
// applies — during which new countries seed the baseline silently.
func (d *NewCountryDetector) withinGracePeriod(event *anomaly.LoginEvent, entries []*anomaly.LoginEntry) bool {
	if d.bootstrapGracePeriod <= 0 {
		return false
	}
	oldest := entries[len(entries)-1].Timestamp
	return event.Timestamp.Sub(oldest) < d.bootstrapGracePeriod
}

// baselineCountryList renders the distinct non-empty country codes
// seen in the baseline as a comma-joined string. Surfaced as
// evidence so operators see "user was in US/CA; this was from RU."
func baselineCountryList(entries []*anomaly.LoginEntry) string {
	seenCountries := make(map[string]bool)
	for _, e := range entries {
		if e.CountryCode != "" {
			seenCountries[e.CountryCode] = true
		}
	}
	baselineList := ""
	for c := range seenCountries {
		if baselineList != "" {
			baselineList += ","
		}
		baselineList += c
	}
	return baselineList
}

// computeUAHash rebuilds the same hash HashLoginEntry would have
// produced, so detectors comparing across read+write paths see the
// same fingerprint. Pulled out as a helper because both new-device
// (write-time hash check) and the runner's stamp (write-time hash
// generation) need it.
func computeUAHash(event *anomaly.LoginEvent, ipSalt []byte) string {
	if event == nil || event.UserAgent == "" {
		return ""
	}
	entry := defaultimpl.HashLoginEntry(event, ipSalt)
	if entry == nil {
		return ""
	}
	return entry.UAFingerprintHash
}

// Compile-time interface assertions.
var (
	_ anomaly.Detector = (*NewDeviceDetector)(nil)
	_ anomaly.Detector = (*NewCountryDetector)(nil)
)
