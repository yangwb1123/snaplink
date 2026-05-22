package anomaly_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/defaultimpl/anomaly"
	"github.com/snaplink/sso/geo"
)

// Fixture coordinates spanning known city pairs — pre-computed so
// tests are deterministic + fast (no haversine surprises).
var (
	sfo = struct{ lat, lon float64 }{37.6213, -122.3790} // San Francisco
	jfk = struct{ lat, lon float64 }{40.6413, -73.7781}  // New York JFK
	pek = struct{ lat, lon float64 }{40.0801, 116.5846}  // Beijing PEK
	lhr = struct{ lat, lon float64 }{51.4700, -0.4543}   // London Heathrow
)

func newDetector(t *testing.T, opts ...anomaly.ImpossibleTravelOption) (*anomaly.ImpossibleTravelDetector, sso.RecentLoginStore) {
	t.Helper()
	store := defaultimpl.NewMemoryRecentLoginStore()
	d, err := anomaly.NewImpossibleTravelDetector(store, []byte("salt"), opts...)
	if err != nil {
		t.Fatalf("NewImpossibleTravelDetector: %v", err)
	}
	return d, store
}

func TestImpossibleTravel_NewSubjectNoAnomaly(t *testing.T) {
	// First login for a subject → no prior history → no signal.
	d, _ := newDetector(t)
	event := &sso.LoginEvent{
		SubjectID: "alice",
		Outcome:   "success",
		Timestamp: time.Now(),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	}
	got, err := d.Inspect(context.Background(), event)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("first login should be anomaly-free; got %v", got)
	}
}

func TestImpossibleTravel_SameCityNoAnomaly(t *testing.T) {
	// Same city, 5 minutes apart — well below the 10km floor.
	d, _ := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-5 * time.Minute),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		// Same SFO airport coords.
		Geo: &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	if len(got) != 0 {
		t.Errorf("same-city login should not flag: %v", got)
	}
}

func TestImpossibleTravel_SF_to_NY_24h_NoAnomaly(t *testing.T) {
	// SF → NY in 24 hours: ~4100km / 24h ≈ 170 km/h. Below
	// 800 ceiling — legitimate travel.
	d, _ := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-24 * time.Hour),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: jfk.lat, Longitude: jfk.lon, CountryCode: "US"},
	})
	if len(got) != 0 {
		t.Errorf("24h SF→NY should not flag: %v", got)
	}
}

func TestImpossibleTravel_SF_to_NY_5min_Critical(t *testing.T) {
	// SF → NY in 5 minutes: ~4100km / 0.083h ≈ 49,400 km/h. Way
	// past supersonic — critical severity.
	d, _ := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-5 * time.Minute),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: jfk.lat, Longitude: jfk.lon, CountryCode: "US"},
	})
	if len(got) != 1 {
		t.Fatalf("5min SF→NY should flag exactly 1 anomaly; got %d", len(got))
	}
	a := got[0]
	if a.Type != anomaly.DetectorTypeImpossibleTravel {
		t.Errorf("type = %q, want impossible_travel", a.Type)
	}
	if a.Severity != sso.AnomalySeverityCritical {
		t.Errorf("severity = %q, want critical at this speed", a.Severity)
	}
	if a.Evidence["prior_country_code"] != "US" || a.Evidence["current_country_code"] != "US" {
		t.Errorf("evidence missing countries: %v", a.Evidence)
	}
	if a.Evidence["distance_km"] == "" || a.Evidence["implied_speed_kmh"] == "" {
		t.Errorf("evidence missing computed metrics: %v", a.Evidence)
	}
}

func TestImpossibleTravel_SF_to_London_30min_Warn(t *testing.T) {
	// SF → London ~8600km in 30min = 17,200 km/h. Past 2000 threshold
	// → critical (not warn — our threshold is 2000+ km/h for critical).
	d, _ := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-30 * time.Minute),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: lhr.lat, Longitude: lhr.lon, CountryCode: "GB"},
	})
	if len(got) != 1 || got[0].Severity != sso.AnomalySeverityCritical {
		t.Errorf("SF→London in 30min should be critical: %+v", got)
	}
}

func TestImpossibleTravel_BorderlineSpeedIsWarn(t *testing.T) {
	// Borderline speed: ~1200 km/h (between 800 ceiling + 2000
	// critical) → warn severity.
	d, _ := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	// SF → JFK distance ≈ 4100 km. In 3.42h ≈ 1199 km/h.
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-205 * time.Minute), // 3.42h
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: jfk.lat, Longitude: jfk.lon, CountryCode: "US"},
	})
	if len(got) != 1 {
		t.Fatalf("borderline should flag: %v", got)
	}
	if got[0].Severity != sso.AnomalySeverityWarn {
		t.Errorf("borderline (~1200 kmh) should be warn, got %q", got[0].Severity)
	}
}

func TestImpossibleTravel_MissingGeoSkipsCheck(t *testing.T) {
	// Detector should not flag when geo is unavailable — no false
	// positives for ops without lat/lon-capable providers.
	d, _ := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-5 * time.Minute),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       nil, // no geo provider available for this login
	})
	if len(got) != 0 {
		t.Errorf("missing geo should skip check: %v", got)
	}
}

func TestImpossibleTravel_PriorMissingLatLonSkipsCheck(t *testing.T) {
	// First login has no lat/lon (e.g. geo provider returned only
	// country) → second login has full geo → can't compute distance
	// → skip.
	d, store := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_ = store.Append(ctx, &sso.LoginEntry{
		SubjectID:   "alice",
		CountryCode: "US",
		Timestamp:   now.Add(-5 * time.Minute),
		// Latitude/Longitude both 0 (geo provider didn't populate).
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: jfk.lat, Longitude: jfk.lon, CountryCode: "US"},
	})
	if len(got) != 0 {
		t.Errorf("prior without lat/lon should skip: %v", got)
	}
}

func TestImpossibleTravel_OutOfWindowPriorIgnored(t *testing.T) {
	// Prior login from 48h ago — outside default 24h window. Even
	// if computed speed exceeded ceiling, we shouldn't flag.
	d, _ := newDetector(t, anomaly.WithImpossibleTravelWindow(24*time.Hour))
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-48 * time.Hour),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: pek.lat, Longitude: pek.lon, CountryCode: "CN"},
	})
	if len(got) != 0 {
		t.Errorf("48h-old prior should be out of window: %v", got)
	}
}

func TestImpossibleTravel_CustomMaxSpeedHonored(t *testing.T) {
	// Tighten ceiling to 200 km/h — a 4100km SF→JFK in 24h
	// (170 km/h normally fine) now flags.
	d, _ := newDetector(t, anomaly.WithImpossibleTravelMaxSpeed(100))
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now.Add(-24 * time.Hour),
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: jfk.lat, Longitude: jfk.lon, CountryCode: "US"},
	})
	if len(got) != 1 {
		t.Errorf("custom 100km/h ceiling should flag SF→NY in 24h (170kmh)")
	}
}

func TestImpossibleTravel_NilEventReturnsNoAnomaly(t *testing.T) {
	d, _ := newDetector(t)
	got, err := d.Inspect(context.Background(), nil)
	if err != nil {
		t.Fatalf("nil event: %v", err)
	}
	if got != nil {
		t.Errorf("nil event: got %v", got)
	}
}

func TestImpossibleTravel_EmptySubjectReturnsNoAnomaly(t *testing.T) {
	d, _ := newDetector(t)
	got, err := d.Inspect(context.Background(), &sso.LoginEvent{Outcome: "failure"})
	if err != nil {
		t.Fatalf("empty subject: %v", err)
	}
	if got != nil {
		t.Errorf("empty subject: got %v", got)
	}
}

func TestImpossibleTravel_AppendsEvenWhenNoAnomaly(t *testing.T) {
	// The "writes uncondi tionally" invariant — subsequent calls see
	// this event as "previous" even though it didn't itself flag.
	d, store := newDetector(t)
	ctx := context.Background()
	now := time.Now()
	_, _ = d.Inspect(ctx, &sso.LoginEvent{
		SubjectID: "alice",
		Timestamp: now,
		Geo:       &geo.GeoInfo{Latitude: sfo.lat, Longitude: sfo.lon, CountryCode: "US"},
	})
	got, _ := store.Recent(ctx, "alice", time.Time{}, 0)
	if len(got) != 1 {
		t.Errorf("Inspect should append: %d entries, want 1", len(got))
	}
}

func TestImpossibleTravel_NilStoreErrors(t *testing.T) {
	_, err := anomaly.NewImpossibleTravelDetector(nil, []byte("salt"))
	if err == nil {
		t.Fatal("nil store should error")
	}
}

func TestImpossibleTravel_NameIsStableWireString(t *testing.T) {
	d, _ := newDetector(t)
	if got := d.Name(); got != anomaly.DetectorTypeImpossibleTravel {
		t.Errorf("Name() = %q, want %q", got, anomaly.DetectorTypeImpossibleTravel)
	}
	if anomaly.DetectorTypeImpossibleTravel != "impossible_travel" {
		t.Errorf("wire string drifted: %q", anomaly.DetectorTypeImpossibleTravel)
	}
}
