package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/platform/metrics"
)

// rateLimitHitValue returns the sso_rate_limit_hits_total value for the given
// tenant label, or 0 if the series hasn't been observed.
func rateLimitHitValue(t *testing.T, m *metrics.Metrics, tenant string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != metrics.NameRateLimitHitsTotal {
			continue
		}
		for _, mm := range mf.GetMetric() {
			for _, lp := range mm.GetLabel() {
				if lp.GetName() == metrics.LabelTenant && lp.GetValue() == tenant {
					return mm.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func rejectOnce(mw func(http.Handler) http.Handler) *httptest.ResponseRecorder {
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

// TestMiddleware_RateLimitHitsDefaultUnknownTenant proves a rejection with no
// TenantKeyFunc wired lands on TenantLabelUnknown — the single-tenant-safe
// default — so the metric works without any tenant resolution configured.
func TestMiddleware_RateLimitHitsDefaultUnknownTenant(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	mw := ratelimit.Middleware(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1, 1),
		Key:     func(_ *http.Request) string { return "k" },
		Metrics: m,
	})
	rejectOnce(mw) // consume the burst
	if rec := rejectOnce(mw); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if got := rateLimitHitValue(t, m, metrics.TenantLabelUnknown); got != 1 {
		t.Fatalf("sso_rate_limit_hits_total{tenant=unknown} = %v, want 1", got)
	}
}

// TestMiddleware_RateLimitHitsResolvedTenant proves a wired TenantKeyFunc's
// return value becomes the label, and that it is called ONLY on the reject
// path (never on the allowed request that consumes the burst).
func TestMiddleware_RateLimitHitsResolvedTenant(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	calls := 0
	mw := ratelimit.Middleware(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1, 1),
		Key:     func(_ *http.Request) string { return "k" },
		Metrics: m,
		TenantKeyFunc: func(_ *http.Request) string {
			calls++
			return "acme"
		},
	})
	rejectOnce(mw) // allowed — must NOT invoke TenantKeyFunc
	if calls != 0 {
		t.Fatalf("TenantKeyFunc called %d times on allowed request, want 0", calls)
	}
	rejectOnce(mw) // rejected — invokes TenantKeyFunc
	if calls != 1 {
		t.Fatalf("TenantKeyFunc called %d times on rejected request, want 1", calls)
	}
	if got := rateLimitHitValue(t, m, "acme"); got != 1 {
		t.Fatalf("sso_rate_limit_hits_total{tenant=acme} = %v, want 1", got)
	}
}

// TestMiddleware_RateLimitHitsEmptyResolutionFallsBackToUnknown proves an
// empty TenantKeyFunc result (host didn't resolve to a tenant) still falls
// back to TenantLabelUnknown rather than an empty-string label.
func TestMiddleware_RateLimitHitsEmptyResolutionFallsBackToUnknown(t *testing.T) {
	t.Parallel()
	m := metrics.New()
	mw := ratelimit.Middleware(ratelimit.Policy{
		Default:       ratelimit.NewMemoryLimiter(1, 1),
		Key:           func(_ *http.Request) string { return "k" },
		Metrics:       m,
		TenantKeyFunc: func(_ *http.Request) string { return "" },
	})
	rejectOnce(mw)
	rejectOnce(mw)
	if got := rateLimitHitValue(t, m, metrics.TenantLabelUnknown); got != 1 {
		t.Fatalf("sso_rate_limit_hits_total{tenant=unknown} = %v, want 1", got)
	}
}

// TestMiddleware_NoMetricsIsNoop proves a Policy with no Metrics wired never
// panics on rejection (zero traffic when WithMetrics isn't configured).
func TestMiddleware_NoMetricsIsNoop(t *testing.T) {
	t.Parallel()
	mw := ratelimit.Middleware(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(1, 1),
		Key:     func(_ *http.Request) string { return "k" },
	})
	rejectOnce(mw)
	if rec := rejectOnce(mw); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}
