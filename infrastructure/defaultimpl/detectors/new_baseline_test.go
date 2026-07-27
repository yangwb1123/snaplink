package detectors_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/detectors"
	"github.com/yangwb1123/snaplink/platform/geo"
)

// --- NewDeviceDetector ---

func newDeviceDetector(t *testing.T, opts ...detectors.NewDeviceOption) (*detectors.NewDeviceDetector, anomaly.RecentLoginStore) {
	t.Helper()
	store := defaultimpl.NewMemoryRecentLoginStore()
	d, err := detectors.NewNewDeviceDetector(store, []byte("salt"), opts...)
	if err != nil {
		t.Fatalf("NewNewDeviceDetector: %v", err)
	}
	return d, store
}

func seedDeviceHistory(t *testing.T, store anomaly.RecentLoginStore, subject, ua string, ipSalt []byte, ts time.Time) {
	t.Helper()
	entry := defaultimpl.HashLoginEntry(&anomaly.LoginEvent{
		SubjectID: subject,
		UserAgent: ua,
		Timestamp: ts,
	}, ipSalt)
	if entry == nil {
		t.Fatal("HashLoginEntry returned nil")
	}
	if err := store.Append(context.Background(), entry); err != nil {
		t.Fatalf("seed Append: %v", err)
	}
}

func TestNewDevice_FirstLoginNoSignal(t *testing.T) {
	t.Parallel()
	d, _ := newDeviceDetector(t)
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "Browser/1",
		Timestamp: time.Now(),
	})
	if len(got) != 0 {
		t.Errorf("first login should not flag: %v", got)
	}
}

func TestNewDevice_KnownUANoSignal(t *testing.T) {
	t.Parallel()
	d, store := newDeviceDetector(t, detectors.WithNewDeviceBootstrapGracePeriod(0))
	now := time.Now()
	// Seed alice with Browser/1 ten days ago (past grace).
	seedDeviceHistory(t, store, "alice", "Browser/1", []byte("salt"), now.Add(-10*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "Browser/1", // same UA
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("known UA should not flag: %v", got)
	}
}

func TestNewDevice_NewUAFlags(t *testing.T) {
	t.Parallel()
	d, store := newDeviceDetector(t, detectors.WithNewDeviceBootstrapGracePeriod(0))
	now := time.Now()
	seedDeviceHistory(t, store, "alice", "Browser/1", []byte("salt"), now.Add(-10*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "Browser/2", // different UA
		Timestamp: now,
	})
	if len(got) != 1 {
		t.Fatalf("new UA should flag: %v", got)
	}
	if got[0].Type != detectors.DetectorTypeNewDevice {
		t.Errorf("type = %q", got[0].Type)
	}
	if got[0].Severity != anomaly.SeverityWarn {
		t.Errorf("severity = %q, want warn", got[0].Severity)
	}
	if got[0].Evidence["baseline_entries"] != "1" {
		t.Errorf("evidence baseline_entries: %v", got[0].Evidence)
	}
}

func TestNewDevice_EmptyUASkips(t *testing.T) {
	t.Parallel()
	d, store := newDeviceDetector(t, detectors.WithNewDeviceBootstrapGracePeriod(0))
	now := time.Now()
	seedDeviceHistory(t, store, "alice", "Browser/1", []byte("salt"), now.Add(-10*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "", // no UA header
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("empty UA should skip: %v", got)
	}
}

func TestNewDevice_BootstrapGraceSuppressesFlag(t *testing.T) {
	t.Parallel()
	d, store := newDeviceDetector(t,
		detectors.WithNewDeviceBootstrapGracePeriod(7*24*time.Hour),
	)
	now := time.Now()
	// Seed first login 2 days ago (within 7-day grace).
	seedDeviceHistory(t, store, "alice", "Browser/1", []byte("salt"), now.Add(-2*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "Browser/2", // would-be new device
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("within grace period should not flag: %v", got)
	}
}

func TestNewDevice_OutsideGraceFlagsNewUA(t *testing.T) {
	t.Parallel()
	d, store := newDeviceDetector(t,
		detectors.WithNewDeviceBootstrapGracePeriod(7*24*time.Hour),
	)
	now := time.Now()
	seedDeviceHistory(t, store, "alice", "Browser/1", []byte("salt"), now.Add(-10*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "Browser/2",
		Timestamp: now,
	})
	if len(got) != 1 {
		t.Errorf("outside grace + new UA should flag: %v", got)
	}
}

func TestNewDevice_OutOfBaselineWindowSkips(t *testing.T) {
	t.Parallel()
	// Seeded entry is 60 days ago — outside the 30-day default window.
	d, store := newDeviceDetector(t, detectors.WithNewDeviceBootstrapGracePeriod(0))
	now := time.Now()
	seedDeviceHistory(t, store, "alice", "Browser/1", []byte("salt"), now.Add(-60*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		UserAgent: "Browser/2",
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("out-of-window history should yield zero baseline → no signal: %v", got)
	}
}

func TestNewDevice_NilStoreErrors(t *testing.T) {
	t.Parallel()
	_, err := detectors.NewNewDeviceDetector(nil, []byte("salt"))
	if err == nil {
		t.Error("nil store should error")
	}
}

func TestNewDevice_NameStableWireString(t *testing.T) {
	t.Parallel()
	d, _ := newDeviceDetector(t)
	if got := d.Name(); got != "new_device" {
		t.Errorf("Name = %q, want new_device", got)
	}
}

// --- NewCountryDetector ---

func newCountryDetector(t *testing.T, opts ...detectors.NewCountryOption) (*detectors.NewCountryDetector, anomaly.RecentLoginStore) {
	t.Helper()
	store := defaultimpl.NewMemoryRecentLoginStore()
	d, err := detectors.NewNewCountryDetector(store, opts...)
	if err != nil {
		t.Fatalf("NewNewCountryDetector: %v", err)
	}
	return d, store
}

func seedCountryHistory(t *testing.T, store anomaly.RecentLoginStore, subject, cc string, ts time.Time) {
	t.Helper()
	if err := store.Append(context.Background(), &anomaly.LoginEntry{
		SubjectID:   subject,
		CountryCode: cc,
		Timestamp:   ts,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestNewCountry_KnownCountryNoSignal(t *testing.T) {
	t.Parallel()
	d, store := newCountryDetector(t, detectors.WithNewCountryBootstrapGracePeriod(0))
	now := time.Now()
	seedCountryHistory(t, store, "alice", "US", now.Add(-30*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Geo:       &geo.GeoInfo{CountryCode: "US"},
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("known country: %v", got)
	}
}

func TestNewCountry_NewCountryFlags(t *testing.T) {
	t.Parallel()
	d, store := newCountryDetector(t, detectors.WithNewCountryBootstrapGracePeriod(0))
	now := time.Now()
	seedCountryHistory(t, store, "alice", "US", now.Add(-30*24*time.Hour))
	seedCountryHistory(t, store, "alice", "CA", now.Add(-15*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Geo:       &geo.GeoInfo{CountryCode: "RU"},
		Timestamp: now,
	})
	if len(got) != 1 {
		t.Fatalf("new country should flag: %v", got)
	}
	a := got[0]
	if a.Type != detectors.DetectorTypeNewCountry {
		t.Errorf("type = %q", a.Type)
	}
	if a.Evidence["current_country"] != "RU" {
		t.Errorf("current_country: %v", a.Evidence)
	}
	baseline := a.Evidence["baseline_countries"]
	if !strings.Contains(baseline, "US") || !strings.Contains(baseline, "CA") {
		t.Errorf("baseline_countries should contain US+CA: %q", baseline)
	}
}

func TestNewCountry_BootstrapGraceSuppresses(t *testing.T) {
	t.Parallel()
	d, store := newCountryDetector(t,
		detectors.WithNewCountryBootstrapGracePeriod(7*24*time.Hour),
	)
	now := time.Now()
	seedCountryHistory(t, store, "alice", "US", now.Add(-3*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Geo:       &geo.GeoInfo{CountryCode: "GB"},
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("within grace: %v", got)
	}
}

func TestNewCountry_NoGeoSkips(t *testing.T) {
	t.Parallel()
	d, _ := newCountryDetector(t)
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Geo:       nil,
		Timestamp: time.Now(),
	})
	if got != nil {
		t.Errorf("nil geo: %v", got)
	}
}

func TestNewCountry_EmptyCountrySkips(t *testing.T) {
	t.Parallel()
	d, _ := newCountryDetector(t)
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Geo:       &geo.GeoInfo{CountryCode: ""}, // geo lookup miss
		Timestamp: time.Now(),
	})
	if got != nil {
		t.Errorf("empty CC: %v", got)
	}
}

func TestNewCountry_NilStoreErrors(t *testing.T) {
	t.Parallel()
	_, err := detectors.NewNewCountryDetector(nil)
	if err == nil {
		t.Error("nil store should error")
	}
}

func TestNewCountry_NameStableWireString(t *testing.T) {
	t.Parallel()
	d, _ := newCountryDetector(t)
	if got := d.Name(); got != "new_country" {
		t.Errorf("Name = %q, want new_country", got)
	}
}

func TestNewCountry_OutOfBaselineWindowNoBaseline(t *testing.T) {
	t.Parallel()
	// 180 days ago > 90-day default window → no baseline → first
	// login behavior (no signal).
	d, store := newCountryDetector(t, detectors.WithNewCountryBootstrapGracePeriod(0))
	now := time.Now()
	seedCountryHistory(t, store, "alice", "US", now.Add(-180*24*time.Hour))
	got, _ := d.Inspect(context.Background(), &anomaly.LoginEvent{
		SubjectID: "alice",
		Geo:       &geo.GeoInfo{CountryCode: "RU"},
		Timestamp: now,
	})
	if len(got) != 0 {
		t.Errorf("baseline-less first login: %v", got)
	}
}
