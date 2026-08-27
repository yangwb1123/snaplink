package sso_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestSelfServicePasswordPolicyRejectsHTTPWrite(t *testing.T) {
	t.Parallel()
	env := rcovNewServer(t, sso.WithPasswordPolicy(spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: 12})))
	access, _ := rcovDirectLogin(t, env)
	status, out := rcovPostJSON(t, env.http.URL+"/me/password", access, map[string]any{
		"current_password": "pw", "new_password": "short1",
	})
	if status != http.StatusBadRequest || out["error"] != "password_policy_violation" {
		t.Fatalf("password write = (%d, %v), want 400 password_policy_violation", status, out)
	}
	if strings.Contains(fmt.Sprint(out), "short1") {
		t.Fatalf("password write response leaked candidate password: %v", out)
	}
	if err := env.passwd.VerifyPassword(t.Context(), rcovUser, "pw"); err != nil {
		t.Fatalf("rejected password write changed stored password: %v", err)
	}
}

func TestSetupPasswordPolicyRejectsBeforePersistence(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	permissionStore := permissions.NewMemoryProvider()
	server := sso.NewServer(
		sso.WithSetupWizardEnabled(true),
		sso.WithUserProvider(users),
		sso.WithPasswordCredentialStore(passwords),
		sso.WithPermissionProvider(permissionStore),
		sso.WithPasswordPolicy(spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: 12})),
	)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	status, out := rcovPostJSON(t, httpServer.URL+sso.PathSetup, "", map[string]any{
		"admin": map[string]any{"username": "root", "password": "Short123"},
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_request" {
		t.Fatalf("setup policy rejection = (%d, %v), want 400 invalid_request", status, out)
	}
	if strings.Contains(fmt.Sprint(out), "Short123") {
		t.Fatalf("setup response leaked candidate password: %v", out)
	}
	usersAfter, err := users.List(t.Context())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(usersAfter) != 0 {
		t.Fatalf("policy rejection persisted %d users", len(usersAfter))
	}
	roles, err := permissionStore.ListAllRoles(t.Context(), "")
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("policy rejection persisted %d roles", len(roles))
	}
	has, err := passwords.HasPassword(t.Context(), "root")
	if err != nil {
		t.Fatalf("check password: %v", err)
	}
	if has {
		t.Fatal("policy rejection persisted an admin credential")
	}
}

type countingPasswordPolicy struct{ calls int }

func (p *countingPasswordPolicy) ValidatePassword(context.Context, string) error {
	p.calls++
	return nil
}

func TestSetupRecoveryDoesNotRevalidateExistingPassword(t *testing.T) {
	t.Parallel()
	policy := &countingPasswordPolicy{}
	server := sso.NewServer(
		sso.WithSetupWizardEnabled(true),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithPasswordCredentialStore(defaultimpl.NewMemoryPasswordCredentialStore()),
		sso.WithPermissionProvider(permissions.NewMemoryProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithPasswordPolicy(policy),
	)
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)

	password := "valid-password1"
	status, _ := rcovPostJSON(t, httpServer.URL+sso.PathSetup, "", map[string]any{
		"admin": map[string]any{"username": "root", "password": password},
	})
	if status != http.StatusOK || policy.calls != 1 {
		t.Fatalf("initial setup = (%d, policy calls=%d), want 200 and one validation", status, policy.calls)
	}
	status, out := rcovPostJSON(t, httpServer.URL+sso.PathSetup, "", map[string]any{
		"admin": map[string]any{"username": "root", "password": password},
		"application": map[string]any{
			"name": "Recovered", "recovery_client_id": "recover-id",
			"recovery_client_secret": "recover-secret",
		},
	})
	if status != http.StatusOK || out["recovered"] != true {
		t.Fatalf("recovery = (%d, %v), want 200 recovered", status, out)
	}
	if policy.calls != 1 {
		t.Fatalf("recovery revalidated an existing password: calls=%d, want 1", policy.calls)
	}
}
