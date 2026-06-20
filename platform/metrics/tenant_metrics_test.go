package metrics_test

import (
	"testing"

	"github.com/snaplink/sso/platform/metrics"
)

// gatherSeries returns the gathered samples for the named metric as a map
// keyed by a canonical "label=value,..." string → counter value. Uses the
// registry's own Gather (core client_golang) — no testutil dep.
func gatherSeries(t *testing.T, m *metrics.Metrics, name string) map[string]float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, metric := range mf.GetMetric() {
			key := ""
			for _, lp := range metric.GetLabel() {
				if key != "" {
					key += ","
				}
				key += lp.GetName() + "=" + lp.GetValue()
			}
			out[key] = metric.GetCounter().GetValue()
		}
	}
	return out
}

// TestTenantMetrics_DefaultOff proves the opt-in vectors are NOT built or
// registered by a plain metrics.New() — the per-tenant series are absent
// until EnableTenantMetrics is called (byte-identical off, §5).
func TestTenantMetrics_DefaultOff(t *testing.T) {
	m := metrics.New()
	if m.LoginAttemptsByTenantTotal != nil {
		t.Fatal("LoginAttemptsByTenantTotal must be nil before EnableTenantMetrics")
	}
	if m.TokensIssuedByTenantTotal != nil {
		t.Fatal("TokensIssuedByTenantTotal must be nil before EnableTenantMetrics")
	}
	if got := gatherSeries(t, m, metrics.NameLoginAttemptsByTenantTotal); len(got) != 0 {
		t.Fatalf("per-tenant login series must be absent, got %v", got)
	}
	if got := gatherSeries(t, m, metrics.NameTokensIssuedByTenantTotal); len(got) != 0 {
		t.Fatalf("per-tenant token series must be absent, got %v", got)
	}
}

// TestTenantMetrics_EnableRegistersVectors proves EnableTenantMetrics builds
// + registers both vectors, is idempotent, and that the "other" bucket
// caps cardinality alongside an allowlisted tenant.
func TestTenantMetrics_EnableRegistersVectors(t *testing.T) {
	m := metrics.New()
	m.EnableTenantMetrics()
	if m.LoginAttemptsByTenantTotal == nil || m.TokensIssuedByTenantTotal == nil {
		t.Fatal("EnableTenantMetrics must construct both vectors")
	}
	// Idempotent: a second call must not panic (double-register) and must
	// keep the same vector.
	before := m.LoginAttemptsByTenantTotal
	m.EnableTenantMetrics()
	if m.LoginAttemptsByTenantTotal != before {
		t.Fatal("EnableTenantMetrics must be idempotent (same vector)")
	}

	m.LoginAttemptsByTenantTotal.WithLabelValues("acme", "success").Inc()
	m.LoginAttemptsByTenantTotal.WithLabelValues(metrics.TenantLabelOther, "failure").Inc()
	m.TokensIssuedByTenantTotal.WithLabelValues("acme", "jwt").Inc()

	login := gatherSeries(t, m, metrics.NameLoginAttemptsByTenantTotal)
	if got := login["outcome=success,tenant=acme"]; got != 1 {
		t.Fatalf("acme success = %v, want 1 (series=%v)", got, login)
	}
	if got := login["outcome=failure,tenant=other"]; got != 1 {
		t.Fatalf("other failure = %v, want 1 (series=%v)", got, login)
	}
	tok := gatherSeries(t, m, metrics.NameTokensIssuedByTenantTotal)
	if got := tok["strategy=jwt,tenant=acme"]; got != 1 {
		t.Fatalf("acme jwt token = %v, want 1 (series=%v)", got, tok)
	}
}
