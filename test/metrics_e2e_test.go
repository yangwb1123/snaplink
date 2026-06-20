package ssotest

// End-to-end metrics integration — wires a real sso.Server with
// metrics.New(), drives real HTTP through it, scrapes /metrics, and
// asserts the counters reflect what happened. Catches integration
// bugs the unit tests in metrics/ can't (middleware not actually
// installed, /metrics not actually served, recordLoginFailure path
// not actually called, etc.).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
)

// buildMetricsHarness mirrors buildRiskHarness but with metrics
// enabled. Returns the test server + the metrics handle so tests can
// scrape and assert.
func buildMetricsHarness(t *testing.T) (*httptest.Server, *metrics.Metrics) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("metrics-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "m-app",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "s3cret" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)

	prov := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(50)
	recorder := audit.New(sink)

	m := metrics.New()

	srv := sso.NewServer(
		sso.WithIssuer("metrics-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithAuditRecorder(recorder),
		sso.WithMetrics(m),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, m
}

func scrapeServerMetrics(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/metrics status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func TestMetricsE2E_HealthRequestIncrementsHTTPCounter(t *testing.T) {
	srv, _ := buildMetricsHarness(t)

	for i := 0; i < 3; i++ {
		resp, err := http.Get(srv.URL + "/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		_ = resp.Body.Close()
	}

	scrape := scrapeServerMetrics(t, srv)
	if !strings.Contains(scrape, `sso_http_requests_total{method="GET",status_class="2xx"} 3`) {
		t.Errorf("expected 3 successful GETs in scrape, got:\n%s", scrape)
	}
}

func TestMetricsE2E_LoginSuccessIncrementsAuthCounters(t *testing.T) {
	srv, _ := buildMetricsHarness(t)

	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "m-app",
		"credential": map[string]string{"username": "alice", "password": "s3cret"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login = %d body=%s", resp.StatusCode, raw)
	}
	_ = resp.Body.Close()

	scrape := scrapeServerMetrics(t, srv)
	if !strings.Contains(scrape, `sso_login_attempts_total{outcome="success",provider="password"} 1`) {
		t.Errorf("expected login success counter == 1, scrape:\n%s", scrape)
	}
	if !strings.Contains(scrape, `sso_tokens_issued_total{strategy="jwt"} 1`) {
		t.Errorf("expected tokens_issued counter == 1, scrape:\n%s", scrape)
	}
}

func TestMetricsE2E_LoginFailureIncrementsFailureCounter(t *testing.T) {
	srv, _ := buildMetricsHarness(t)

	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  "m-app",
		"credential": map[string]string{"username": "alice", "password": "wrong"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}

	scrape := scrapeServerMetrics(t, srv)
	if !strings.Contains(scrape, `sso_login_attempts_total{outcome="failure",provider="password"} 1`) {
		t.Errorf("expected login failure counter == 1, scrape:\n%s", scrape)
	}
}

func TestMetricsE2E_MetricsEndpointNotInstrumented(t *testing.T) {
	// Critical contract: /metrics MUST NOT show up in
	// sso_http_requests_total — otherwise the counter self-inflates
	// every scrape interval and the dashboard reads pure noise.
	srv, _ := buildMetricsHarness(t)

	// Hit one normal endpoint, then scrape /metrics 5 times.
	resp, _ := http.Get(srv.URL + "/health")
	_ = resp.Body.Close()
	for i := 0; i < 5; i++ {
		scrapeServerMetrics(t, srv)
	}

	final := scrapeServerMetrics(t, srv)
	// /health contributed 1; all scrapes must NOT contribute.
	if !strings.Contains(final, `sso_http_requests_total{method="GET",status_class="2xx"} 1`) {
		t.Errorf("/metrics scrapes inflated the request counter (expected 1 from /health):\n%s", final)
	}
}
