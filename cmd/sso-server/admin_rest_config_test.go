package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// loadAdminRESTConfig builds the smallest source-loaded admin configuration
// with a real admin:* principal. The source load is intentional: command
// defaults are resolved by config.LoadFromSources, not direct struct setup.
func loadAdminRESTConfig(t *testing.T, restLine string) *config.Config {
	t.Helper()
	body := "server:\n  issuer: test-issuer\nadmin:\n  enabled: true\n" + restLine + `permissions:
  enabled: true
  apps:
    - client_id: ""
      roles:
        - code: root
          permissions: ["admin:*"]
  user_roles:
    - user_id: admin-user
      client_id: ""
      roles: [root]
`
	return loadAdminRESTYAML(t, body)
}

func loadAdminRESTYAML(t *testing.T, body string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "admin-rest.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadFromSources(context.Background(), config.NewFileSource(p))
	if err != nil {
		t.Fatalf("LoadFromSources: %v", err)
	}
	return cfg
}

func adminRESTRequest(t *testing.T, cfg *config.Config) int {
	t.Helper()
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer shutdownApp(t, a)
	h, err := buildHTTPHandler(cfg, a, quietLogger())
	if err != nil {
		t.Fatalf("buildHTTPHandler: %v", err)
	}
	issuer := a.tokenIssuers[sso.TokenStrategyJWT]
	access, err := issuer.Issue(context.Background(), &sso.Subject{ID: "admin-user"}, nil)
	if err != nil {
		t.Fatalf("issue admin bearer: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients", nil)
	req.Header.Set("Authorization", "Bearer "+access.AccessToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestAdminRESTConfig_DefaultAndExplicitEnablementReachability(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		restLine string
		wantCode int
	}{
		{name: "omitted", wantCode: http.StatusOK},
		{name: "explicit true", restLine: "  api_rest_enabled: true\n", wantCode: http.StatusOK},
		{name: "explicit false", restLine: "  api_rest_enabled: false\n", wantCode: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := adminRESTRequest(t, loadAdminRESTConfig(t, tc.restLine)); got != tc.wantCode {
				t.Fatalf("GET /api/v1/admin/clients = %d, want %d", got, tc.wantCode)
			}
		})
	}
}
