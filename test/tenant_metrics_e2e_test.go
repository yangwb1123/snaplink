package ssotest

// End-to-end per-tenant metrics — wires a real sso.Server with
// metrics.New() + sso.WithTenantMetricsAllowlist, drives real HTTP logins
// for an allowlisted tenant, a NON-allowlisted tenant, and an untenanted
// client, then scrapes /metrics and asserts the cardinality stays bounded
// to {allowlisted tenant, "other"}. Also asserts that WITHOUT an allowlist
// the per-tenant series never appear (byte-identical off, §5).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/permissions"
)

// buildTenantMetricsHarness builds a metrics-enabled server with three
// clients spanning the tenant-label cases. allowlist nil/empty leaves the
// per-tenant metrics OFF.
func buildTenantMetricsHarness(t *testing.T, allowlist []string) *httptest.Server {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("tenant-metrics-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	// acme-app: tenant on the allowlist.
	clients.AddSeed(&sso.Client{
		ID:                    "acme-app",
		TenantID:              "acme",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	// globex-app: tenant NOT on the allowlist → folds into "other".
	clients.AddSeed(&sso.Client{
		ID:                    "globex-app",
		TenantID:              "globex",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	// untenant-app: no tenant at all → folds into "other".
	clients.AddSeed(&sso.Client{
		ID:                    "untenant-app",
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

	opts := []sso.Option{
		sso.WithIssuer("tenant-metrics-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithAuditRecorder(recorder),
		sso.WithMetrics(m),
	}
	if len(allowlist) > 0 {
		opts = append(opts, sso.WithTenantMetricsAllowlist(allowlist))
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func tenantLoginAs(t *testing.T, srv *httptest.Server, clientID, password string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": "alice", "password": password},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login (%s): %v", clientID, err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestTenantMetricsE2E_NoAllowlist_NoSeries(t *testing.T) {
	srv := buildTenantMetricsHarness(t, nil)

	if got := tenantLoginAs(t, srv, "acme-app", "s3cret"); got != http.StatusOK {
		t.Fatalf("acme login = %d, want 200", got)
	}

	scrape := scrapeServerMetrics(t, srv)
	// The base counters still work...
	if !strings.Contains(scrape, `sso_login_attempts_total{outcome="success",provider="password"} 1`) {
		t.Errorf("base login counter missing:\n%s", scrape)
	}
	// ...but the per-tenant series must be entirely absent (not even a
	// HELP/TYPE line) because the vectors were never registered.
	if strings.Contains(scrape, metrics.NameLoginAttemptsByTenantTotal) {
		t.Errorf("per-tenant login metric leaked with no allowlist:\n%s", scrape)
	}
	if strings.Contains(scrape, metrics.NameTokensIssuedByTenantTotal) {
		t.Errorf("per-tenant token metric leaked with no allowlist:\n%s", scrape)
	}
}

func TestTenantMetricsE2E_BoundedToAllowlistPlusOther(t *testing.T) {
	srv := buildTenantMetricsHarness(t, []string{"acme"})

	// acme (allowlisted): one success.
	if got := tenantLoginAs(t, srv, "acme-app", "s3cret"); got != http.StatusOK {
		t.Fatalf("acme login = %d, want 200", got)
	}
	// globex (NOT allowlisted): one success → folds into "other".
	if got := tenantLoginAs(t, srv, "globex-app", "s3cret"); got != http.StatusOK {
		t.Fatalf("globex login = %d, want 200", got)
	}
	// untenant (no tenant): one success → folds into "other".
	if got := tenantLoginAs(t, srv, "untenant-app", "s3cret"); got != http.StatusOK {
		t.Fatalf("untenant login = %d, want 200", got)
	}
	// A failure on a NON-allowlisted tenant → "other" failure bucket.
	if got := tenantLoginAs(t, srv, "globex-app", "wrong"); got != http.StatusUnauthorized {
		t.Fatalf("globex bad login = %d, want 401", got)
	}

	scrape := scrapeServerMetrics(t, srv)

	// acme stands alone on the allowlist.
	if !strings.Contains(scrape, `sso_login_attempts_by_tenant_total{outcome="success",tenant="acme"} 1`) {
		t.Errorf("acme success bucket wrong:\n%s", scrape)
	}
	if !strings.Contains(scrape, `sso_tokens_issued_by_tenant_total{strategy="jwt",tenant="acme"} 1`) {
		t.Errorf("acme token bucket wrong:\n%s", scrape)
	}
	// globex + untenant both fold into "other": two successes.
	if !strings.Contains(scrape, `sso_login_attempts_by_tenant_total{outcome="success",tenant="other"} 2`) {
		t.Errorf("other success bucket must be 2 (globex+untenant):\n%s", scrape)
	}
	if !strings.Contains(scrape, `sso_login_attempts_by_tenant_total{outcome="failure",tenant="other"} 1`) {
		t.Errorf("other failure bucket must be 1 (globex bad creds):\n%s", scrape)
	}
	// CARDINALITY GATE: the tenant label must NEVER carry the raw
	// non-allowlisted tenant id.
	if strings.Contains(scrape, `tenant="globex"`) {
		t.Errorf("non-allowlisted tenant id leaked as a label (cardinality blowout):\n%s", scrape)
	}

	// Total distinct tenant label values across the per-tenant login
	// metric must be bounded to {acme, other} = 2.
	if got := distinctTenantLabels(scrape, metrics.NameLoginAttemptsByTenantTotal); got > 2 {
		t.Errorf("tenant label cardinality = %d, must be <= len(allowlist)+1 = 2", got)
	}
}

// distinctTenantLabels counts unique tenant="..." label values appearing on
// the named metric in a /metrics scrape.
func distinctTenantLabels(scrape, metricName string) int {
	seen := map[string]struct{}{}
	for _, line := range strings.Split(scrape, "\n") {
		if !strings.HasPrefix(line, metricName+"{") {
			continue
		}
		i := strings.Index(line, `tenant="`)
		if i < 0 {
			continue
		}
		rest := line[i+len(`tenant="`):]
		j := strings.IndexByte(rest, '"')
		if j < 0 {
			continue
		}
		seen[rest[:j]] = struct{}{}
	}
	return len(seen)
}
