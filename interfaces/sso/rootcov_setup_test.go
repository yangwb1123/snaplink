package sso_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

type setupFailOnceClients struct {
	*defaultimpl.MemoryClientStore
	fail bool
}

func (s *setupFailOnceClients) Add(ctx context.Context, client *core.Client) error {
	if s.fail {
		s.fail = false
		return errors.New("temporary client write failure")
	}
	return s.MemoryClientStore.Add(ctx, client)
}

func TestRcovSetupPartialApplicationHasIdempotentRecovery(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	clients := &setupFailOnceClients{
		MemoryClientStore: defaultimpl.NewMemoryClientStore(),
		fail:              true,
	}
	server := sso.NewServer(
		sso.WithSetupWizardEnabled(true),
		sso.WithUserProvider(users),
		sso.WithPasswordCredentialStore(passwords),
		sso.WithPermissionProvider(permissions.NewMemoryProvider()),
		sso.WithClientStore(clients),
	)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	request := map[string]any{
		"admin": map[string]any{"username": "root", "password": "long-enough"},
		"application": map[string]any{
			"name": "Console", "redirect_uris": []string{"https://console.example/cb"},
		},
	}
	status, partial := rcovPostJSON(t, httpServer.URL+sso.PathSetup, "", request)
	if status != 207 || partial["status"] != "partial_success" {
		t.Fatalf("partial setup = (%d, %v), want 207 partial_success", status, partial)
	}
	created := partial["created"].(map[string]any)
	recovery := partial["recovery"].(map[string]any)
	recoveryApp := recovery["application"].(map[string]any)
	if created["admin"] != "root" || recoveryApp["recovery_client_id"] == "" {
		t.Fatalf("partial response lacks created/recovery resources: %v", partial)
	}

	request["application"] = recoveryApp
	status, recovered := rcovPostJSON(t, httpServer.URL+sso.PathSetup, "", request)
	if status != 200 || recovered["recovered"] != true {
		t.Fatalf("recovery = (%d, %v), want 200 recovered", status, recovered)
	}
	app := recovered["created"].(map[string]any)["application"].(map[string]any)
	status, repeated := rcovPostJSON(t, httpServer.URL+sso.PathSetup, "", request)
	repeatedApp := repeated["created"].(map[string]any)["application"].(map[string]any)
	if status != 200 || repeatedApp["client_id"] != app["client_id"] {
		t.Fatalf("repeated recovery created a different client: %v then %v", app, repeatedApp)
	}
}
