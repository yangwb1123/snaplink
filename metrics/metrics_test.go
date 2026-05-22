package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/snaplink/sso/metrics"
)

func TestNew_ConstructsAllVectors(t *testing.T) {
	m := metrics.New()
	if m.Registry == nil {
		t.Fatal("Registry must not be nil")
	}
	if m.HTTPRequestsTotal == nil || m.HTTPRequestDuration == nil {
		t.Error("HTTP collectors not initialized")
	}
	if m.LoginAttemptsTotal == nil || m.TokensIssuedTotal == nil {
		t.Error("auth-flow collectors not initialized")
	}
	if m.RiskDecisionsTotal == nil {
		t.Error("risk decisions collector not initialized")
	}
}

func TestMiddleware_NilMetricsIsIdentity(t *testing.T) {
	// Wrapping with nil Metrics MUST NOT alter behavior — operators
	// who don't wire WithMetrics get the unmodified router.
	mw := metrics.Middleware(nil)
	called := false
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("inner handler not invoked through nil-middleware identity")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
}

func TestMiddleware_CountsRequestsByMethodAndStatusClass(t *testing.T) {
	m := metrics.New()
	mw := metrics.Middleware(m)
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusOK)
		case "/bad":
			w.WriteHeader(http.StatusBadRequest)
		case "/boom":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	for _, p := range []string{"/ok", "/ok", "/bad", "/boom"} {
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
	}

	scrape := scrapeMetrics(t, m)
	mustContain(t, scrape, `sso_http_requests_total{method="GET",status_class="2xx"} 2`)
	mustContain(t, scrape, `sso_http_requests_total{method="GET",status_class="4xx"} 1`)
	mustContain(t, scrape, `sso_http_requests_total{method="GET",status_class="5xx"} 1`)
}

func TestMiddleware_ImplicitOKCountsAs2xx(t *testing.T) {
	// Handlers that never call WriteHeader implicitly return 200.
	// Without the statusRecorder.Write hook this would mis-classify
	// as the zero-value status_class.
	m := metrics.New()
	mw := metrics.Middleware(m)
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("implicit 200"))
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	scrape := scrapeMetrics(t, m)
	mustContain(t, scrape, `sso_http_requests_total{method="GET",status_class="2xx"} 1`)
}

func TestMiddleware_RecordsLatencyHistogram(t *testing.T) {
	m := metrics.New()
	mw := metrics.Middleware(m)
	wrapped := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", nil))

	scrape := scrapeMetrics(t, m)
	mustContain(t, scrape, `sso_http_request_duration_seconds_count{method="POST"} 1`)
}

func TestMetrics_DirectCountersAreScrapable(t *testing.T) {
	// The non-HTTP counters (login attempts, tokens, risk, mfa) are
	// incremented manually from handler.go / audit_handler.go /
	// handle_mfa.go. Just prove they roundtrip through the registry.
	m := metrics.New()
	m.LoginAttemptsTotal.WithLabelValues("password", "success").Inc()
	m.LoginAttemptsTotal.WithLabelValues("password", "failure").Add(3)
	m.TokensIssuedTotal.WithLabelValues("jwt").Inc()
	m.RiskDecisionsTotal.WithLabelValues("deny").Inc()
	m.MFAChallengesTotal.WithLabelValues("totp").Inc()
	m.MFAChallengesTotal.WithLabelValues("webauthn").Add(2)
	m.MFACompletionsTotal.WithLabelValues("totp", "success").Inc()
	m.MFACompletionsTotal.WithLabelValues("totp", "failure").Add(4)
	m.MFACompletionsTotal.WithLabelValues("webauthn", "success").Inc()

	scrape := scrapeMetrics(t, m)
	mustContain(t, scrape, `sso_login_attempts_total{outcome="success",provider="password"} 1`)
	mustContain(t, scrape, `sso_login_attempts_total{outcome="failure",provider="password"} 3`)
	mustContain(t, scrape, `sso_tokens_issued_total{strategy="jwt"} 1`)
	mustContain(t, scrape, `sso_risk_decisions_total{decision="deny"} 1`)
	mustContain(t, scrape, `sso_mfa_challenges_total{mfa_method="totp"} 1`)
	mustContain(t, scrape, `sso_mfa_challenges_total{mfa_method="webauthn"} 2`)
	mustContain(t, scrape, `sso_mfa_completions_total{mfa_method="totp",outcome="success"} 1`)
	mustContain(t, scrape, `sso_mfa_completions_total{mfa_method="totp",outcome="failure"} 4`)
	mustContain(t, scrape, `sso_mfa_completions_total{mfa_method="webauthn",outcome="success"} 1`)
}

func scrapeMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}).
		ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics returned %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	return string(body)
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("scrape missing %q\nactual:\n%s", needle, haystack)
	}
}
