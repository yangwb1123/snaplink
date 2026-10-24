package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestBuildAppPostgresSecurityStores(t *testing.T) {
	if os.Getenv("SSO_TEST_POSTGRES_DSN") == "" {
		t.Fatal("owned PostgreSQL fixture required for security backend coverage")
	}
	for _, mode := range []string{"lockout", "revocations", "both-normalized"} {
		t.Run(mode, func(t *testing.T) {
			cfg := sessionSchemaConfig(t, "memory", "postgres")
			cfg.Permissions.Backend = "postgres"
			if mode != "revocations" {
				cfg.Security.AccountLockout = config.AccountLockoutConfig{Enabled: true, Backend: " POSTGRES "}
			}
			if mode != "lockout" {
				cfg.Keys.Signing.RevocationBackend = " POSTGRES "
			}
			a := openSessionSchemaApp(t, cfg)
			handler, err := buildHTTPHandler(cfg, a, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			reply := httptest.NewRecorder()
			handler.ServeHTTP(reply, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if reply.Code != http.StatusOK {
				t.Fatalf("postgres security readiness=%d: %s", reply.Code, reply.Body.String())
			}
		})
	}
}
