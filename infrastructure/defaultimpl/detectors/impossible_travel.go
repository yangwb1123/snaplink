// Package detectors ships the reference [anomaly.Detector]
// implementations. Each detector is independent + composable —
// operators wire any subset via WithAnomalyRunner; richer custom
// scorers implement [anomaly.Detector] directly + query their
// own state.
//
// All detectors in this package read state via the operator-supplied
// [anomaly.RecentLoginStore] / [sso.KnownDeviceStore] etc — they do NOT
// own a database connection. The state stores are wired separately
// (memory peer for single-replica, sqlite peer for cluster-shared),
// and detectors compose with whichever the operator chose.
package detectors

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// DetectorTypeImpossibleTravel is the wire-stable [anomaly.Signal.Type]
// surfaced by [ImpossibleTravelDetector]. Operators alerting on this
// detector branch on this string in their SIEM rules.
const DetectorTypeImpossibleTravel = anomaly.SignalTypeImpossibleTravel

// MaxRealisticSpeedKmh is the speed ceiling above which two
// consecutive logins are considered physically impossible. 800 km/h
// is the commercial-aviation cruise envelope (Boeing 737 ≈ 850;
// 800 leaves slight headroom for clock skew + the rare Concorde-
// class jet still in service). Operators with frequent business-jet
// travelers can tighten via WithImpossibleTravelMaxSpeed.
//
// Why not faster: a 900km/h ceiling lets the detector miss
// continent-jump VPN switches that take ~10 minutes — the very
// signal we want to surface.
const MaxRealisticSpeedKmh = 800.0

// ImpossibleTravelDetector flags a login as anomalous when the
// physical distance between this login's geo point and the most
// recent prior login's geo point implies a travel speed faster than
// commercial aviation can sustain.
//
// State requirements:
//
//   - Reads the previous login from a [anomaly.RecentLoginStore]. Empty
//     history → first login for the subject → no anomaly (the
//     detector needs at least one prior data point).
//   - Both the current event AND the previous entry must carry
//     populated Latitude+Longitude. Either side missing → skip the
//     distance check (operators without lat/lon-capable geo providers
//     get no false-positives from this detector; they still benefit
//     from new-country detection in R6).
//
// Why-this-design:
//
//   - SHIPS WRITES TOO. The detector appends the current event to
//     the store as a side effect of Inspect — this is what makes
//     the "previous login" lookup work for the NEXT call. Operators
//     could centralize this by wiring a separate "writer detector"
//     before the chain, but having every detector self-manage its
//     read+write keeps the SPI flat (no cross-detector
//     dependencies).
//
//   - WRITES UNCONDITIONALLY (even when the event would NOT be
//     surfaced as an anomaly). Future detectors reading the same
//     store (velocity in R5, new-device in R6) need full history.
//
//   - INDEPENDENT OF Outcome. Failed logins also write to the store
//     because the new-device detector wants to see failed attempts
//     for baselining ("user X tried from this UA and got bcrypt-
//     rejected — is it a new device?"). The impossible-travel check
//     itself only fires against the latest entry regardless of its
//     outcome.
type ImpossibleTravelDetector struct {
	store    anomaly.RecentLoginStore
	ipSalt   []byte
	maxSpeed float64
	// historyWindow bounds how far back we'll consider a "previous"
	// login for the speed calculation. Default 24h — older entries
	// would be physically reachable even at walking pace.
	historyWindow time.Duration
}

// ImpossibleTravelOption tunes the detector at construction.
type ImpossibleTravelOption func(*ImpossibleTravelDetector)

// WithImpossibleTravelMaxSpeed overrides the default 800 km/h
// ceiling. Operators with frequent business-jet travelers can
// raise to 1000; consumer-grade B2C deploys can lower to 500.
func WithImpossibleTravelMaxSpeed(kmh float64) ImpossibleTravelOption {
	return func(d *ImpossibleTravelDetector) {
		if kmh > 0 {
			d.maxSpeed = kmh
		}
	}
}

// WithImpossibleTravelWindow overrides the default 24h history
// lookback. Logins older than this are ignored for the speed
// check (anything is reachable in a day's worth of plane hops).
func WithImpossibleTravelWindow(d time.Duration) ImpossibleTravelOption {
	return func(det *ImpossibleTravelDetector) {
		if d > 0 {
			det.historyWindow = d
		}
	}
}

// NewImpossibleTravelDetector returns a detector that consults the
// given [anomaly.RecentLoginStore]. ipSalt is the deployment-stable
// secret used by [defaultimpl.HashLoginEntry] — pass the same
// value used when the AnomalyRunner stamps LoginEntries elsewhere.
//
// store nil → error (the detector is useless without history).
// Empty ipSalt is accepted (memory-only deploys can opt out of
// salting), but production should always supply one.
func NewImpossibleTravelDetector(store anomaly.RecentLoginStore, ipSalt []byte, opts ...ImpossibleTravelOption) (*ImpossibleTravelDetector, error) {
	if store == nil {
		return nil, errors.New("anomaly/impossible_travel: store required")
	}
	d := &ImpossibleTravelDetector{
		store:         store,
		ipSalt:        append([]byte(nil), ipSalt...),
		maxSpeed:      MaxRealisticSpeedKmh,
		historyWindow: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d, nil
}

// Name returns the stable detector identifier.
func (d *ImpossibleTravelDetector) Name() string { return DetectorTypeImpossibleTravel }

// Inspect computes the implied travel speed between the current
// event and the most recent prior entry (within historyWindow). If
// the speed exceeds maxSpeed, surfaces one [anomaly.Signal] with
// evidence: distance_km, elapsed_seconds, implied_speed_kmh, plus
// the two endpoints' country codes for operator context.
//
// Appends the current event to the store unconditionally (even
// when no anomaly fires) so subsequent calls see it as "previous."
func (d *ImpossibleTravelDetector) Inspect(ctx context.Context, event *anomaly.LoginEvent) ([]anomaly.Signal, error) {
	if event == nil || event.SubjectID == "" {
		return nil, nil
	}
	// Compute the result against the existing history BEFORE
	// appending the current event — otherwise the "previous"
	// entry is just the current event.
	var anomalies []anomaly.Signal
	if event.Geo != nil && (event.Geo.Latitude != 0 || event.Geo.Longitude != 0) {
		since := event.Timestamp.Add(-d.historyWindow)
		// limit=1 — only the most recent matters for the speed check.
		prior, err := d.store.Recent(ctx, event.SubjectID, since, 1)
		if err != nil {
			return nil, fmt.Errorf("anomaly/impossible_travel: lookup: %w", err)
		}
		if len(prior) > 0 {
			p := prior[0]
			if p.Latitude != 0 || p.Longitude != 0 {
				if a, ok := d.evaluate(event, p); ok {
					anomalies = append(anomalies, a)
				}
			}
		}
	}

	// Append the current event so the next call sees it as
	// "previous." Best-effort — if the store fails, we still
	// return whatever anomaly we found (the dispatch path doesn't
	// need the append to succeed).
	entry := defaultimpl.HashLoginEntry(event, d.ipSalt)
	if entry != nil {
		_ = d.store.Append(ctx, entry)
	}

	return anomalies, nil
}

// evaluate computes the haversine distance between two
// (lat,lon) points + the implied speed; returns the anomaly +
// true when speed > maxSpeed.
func (d *ImpossibleTravelDetector) evaluate(event *anomaly.LoginEvent, prior *anomaly.LoginEntry) (anomaly.Signal, bool) {
	elapsed := event.Timestamp.Sub(prior.Timestamp)
	if elapsed <= 0 {
		// Clock skew or out-of-order events — skip rather than
		// produce nonsense speeds.
		return anomaly.Signal{}, false
	}
	distanceKm := haversineKm(
		event.Geo.Latitude, event.Geo.Longitude,
		prior.Latitude, prior.Longitude,
	)
	// Skip trivially-close logins (same city wifi vs cellular). A
	// 10km floor avoids flagging gateway IP changes that map to
	// the same metro.
	if distanceKm < 10 {
		return anomaly.Signal{}, false
	}
	hours := elapsed.Hours()
	if hours <= 0 {
		return anomaly.Signal{}, false
	}
	speedKmh := distanceKm / hours
	if speedKmh < d.maxSpeed {
		return anomaly.Signal{}, false
	}
	// Severity scales with how implausible the speed is.
	// 800-2000 km/h ≈ supersonic possible (warn);
	// 2000+ km/h ≈ definitely two real humans (critical).
	severity := anomaly.SeverityWarn
	score := 60
	if speedKmh >= 2000 {
		severity = anomaly.SeverityCritical
		score = 90
	}
	return anomaly.Signal{
		Type:      DetectorTypeImpossibleTravel,
		Severity:  severity,
		Score:     score,
		SubjectID: event.SubjectID,
		Evidence: map[string]string{
			"distance_km":          formatFloat(distanceKm, 1),
			"elapsed_seconds":      formatInt(int64(elapsed.Seconds())),
			"implied_speed_kmh":    formatFloat(speedKmh, 0),
			"prior_country_code":   prior.CountryCode,
			"current_country_code": geoCountry(event),
		},
	}, true
}

// haversineKm returns the great-circle distance in kilometers
// between two (lat, lon) coordinates. The standard formula —
// good to ~0.5% for terrestrial distances; perfectly adequate for
// 800 km/h ceiling checks.
func haversineKm(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadiusKm = 6371.0
	dLat := degToRad(lat2 - lat1)
	dLon := degToRad(lon2 - lon1)
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(degToRad(lat1))*math.Cos(degToRad(lat2))*
			math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	return earthRadiusKm * c
}

func degToRad(deg float64) float64 {
	return deg * math.Pi / 180
}

// geoCountry pulls country_code from event.Geo safely (nil-checked).
func geoCountry(event *anomaly.LoginEvent) string {
	if event.Geo == nil {
		return ""
	}
	return event.Geo.CountryCode
}

// formatFloat / formatInt — small helpers to keep the file
// dependency-light + avoid pulling strconv. Float precision ints.
func formatFloat(f float64, prec int) string {
	// strconv.FormatFloat-equivalent for the common case — uses
	// 'f' format with prec decimals. Implemented manually to avoid
	// a strconv import; precision capped at 6.
	if prec < 0 {
		prec = 0
	}
	if prec > 6 {
		prec = 6
	}
	neg := f < 0
	if neg {
		f = -f
	}
	intPart := int64(f)
	frac := f - float64(intPart)
	mult := 1
	for range prec {
		mult *= 10
	}
	fracInt := int64(frac*float64(mult) + 0.5)
	if fracInt >= int64(mult) {
		// Rounding rolled over.
		intPart++
		fracInt = 0
	}
	intStr := formatInt(intPart)
	if neg {
		intStr = "-" + intStr
	}
	if prec == 0 {
		return intStr
	}
	fracStr := formatInt(fracInt)
	// Pad with leading zeros to match prec.
	for len(fracStr) < prec {
		fracStr = "0" + fracStr
	}
	return intStr + "." + fracStr
}

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Compile-time interface assertion.
var _ anomaly.Detector = (*ImpossibleTravelDetector)(nil)
