package metrics_test

import (
	"testing"

	"github.com/yangwb1123/snaplink/platform/metrics"
)

// TestTokenUsageMetrics_DefaultOff proves the opt-in token-usage vectors are
// NOT built or registered by a plain metrics.New() — zero series until
// EnableTokenUsageMetrics runs (byte-identical off, §5, mirrors
// EnableTenantMetrics).
func TestTokenUsageMetrics_DefaultOff(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	if m.TokenUsageEventsTotal != nil {
		t.Fatal("TokenUsageEventsTotal must be nil before EnableTokenUsageMetrics")
	}
	if m.TokenUsageDroppedTotal != nil {
		t.Fatal("TokenUsageDroppedTotal must be nil before EnableTokenUsageMetrics")
	}
	if m.TokenUsageTrackedBuckets != nil {
		t.Fatal("TokenUsageTrackedBuckets must be nil before EnableTokenUsageMetrics")
	}
	if got := gatherSeries(t, m, metrics.NameTokenUsageEventsTotal); len(got) != 0 {
		t.Fatalf("token-usage events series must be absent, got %v", got)
	}
}

// TestTokenUsageMetrics_ObserveIsNilSafeBeforeEnable proves every Observe*/
// Set* method is a nil-safe no-op before EnableTokenUsageMetrics — the
// recorder's hooks can fire unconditionally without checking whether
// metrics were ever armed.
func TestTokenUsageMetrics_ObserveIsNilSafeBeforeEnable(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	m.ObserveTokenUsageEvent("access", "token") // must not panic
	m.ObserveTokenUsageDropped()                // must not panic
	m.SetTokenUsageTrackedBuckets(5)            // must not panic

	var nilMetrics *metrics.Metrics
	nilMetrics.ObserveTokenUsageEvent("access", "token")
	nilMetrics.ObserveTokenUsageDropped()
	nilMetrics.SetTokenUsageTrackedBuckets(5)
	nilMetrics.EnableTokenUsageMetrics()
}

// TestTokenUsageMetrics_EnableRegistersVectors proves EnableTokenUsageMetrics
// builds + registers all three collectors, is idempotent, and that the
// Observe*/Set* helpers route to the right labels.
func TestTokenUsageMetrics_EnableRegistersVectors(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	m.EnableTokenUsageMetrics()
	if m.TokenUsageEventsTotal == nil || m.TokenUsageDroppedTotal == nil || m.TokenUsageTrackedBuckets == nil {
		t.Fatal("EnableTokenUsageMetrics must construct all three collectors")
	}
	// Idempotent: a second call must not panic (double-register) and must
	// keep the same vector.
	before := m.TokenUsageEventsTotal
	m.EnableTokenUsageMetrics()
	if m.TokenUsageEventsTotal != before {
		t.Fatal("EnableTokenUsageMetrics must be idempotent (same vector)")
	}

	m.ObserveTokenUsageEvent("access", "token")
	m.ObserveTokenUsageEvent("refresh", "introspect")
	m.ObserveTokenUsageDropped()
	m.SetTokenUsageTrackedBuckets(42)

	events := gatherSeries(t, m, metrics.NameTokenUsageEventsTotal)
	if got := events["endpoint=token,kind=access"]; got != 1 {
		t.Fatalf("access/token events = %v, want 1 (series=%v)", got, events)
	}
	if got := events["endpoint=introspect,kind=refresh"]; got != 1 {
		t.Fatalf("refresh/introspect events = %v, want 1 (series=%v)", got, events)
	}
	if got := gatherSeries(t, m, metrics.NameTokenUsageDroppedTotal)[""]; got != 1 {
		t.Fatalf("dropped total = %v, want 1", got)
	}
	if got := gatherGaugeValue(t, m, metrics.NameTokenUsageTrackedBuckets); got != 42 {
		t.Fatalf("tracked buckets gauge = %v, want 42", got)
	}
}

// gatherGaugeValue reads a single no-label Gauge's current value.
// gatherSeries (tenant_metrics_test.go) only reads GetCounter(), which is
// the zero-value proto branch for a Gauge metric family — this is the Gauge
// equivalent, needed because TokenUsageTrackedBuckets is a gauge, not a
// counter.
func gatherGaugeValue(t *testing.T, m *metrics.Metrics, name string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, metric := range mf.GetMetric() {
			return metric.GetGauge().GetValue()
		}
	}
	t.Fatalf("metric %s not found", name)
	return 0
}
