package main

import (
	"context"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestBuildAuthenticators_RuntimeStoreUserCanLogin proves the fix for the
// runtime-user login gap. A password user created AT RUNTIME — self-service
// signup, admin user-create/reset, or the first-run setup wizard — writes its
// credential to the PasswordCredentialStore keyed by its userID (== the login
// username), but the YAML-seeded verifier only knew usernames present in
// authenticators.password.users at boot, so such users could never
// authenticate through the stock binary. buildPasswordAuthVerifier now chains a
// UserProvider-resolving store verifier; this drives Authenticate end-to-end
// with NO YAML users configured.
func TestBuildAuthenticators_RuntimeStoreUserCanLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	store := defaultimpl.NewMemoryPasswordCredentialStore()

	// Simulate the setup wizard / signup: create the user, then set its
	// password in the store keyed by the userID.
	if err := users.CreateOrUpdate(ctx, &sso.User{ID: "root", ExternalID: "root", Provider: "password"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.SetPassword(ctx, "root", "Sup3rSecret!"); err != nil {
		t.Fatalf("set password: %v", err)
	}

	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true} // deliberately NO YAML users
	auths, _, _, _, err := serverbuildauthn.BuildAuthenticators(cfg, quietLogger(), store, users, nil)
	if err != nil {
		t.Fatalf("BuildAuthenticators: %v", err)
	}
	var pw sso.Authenticator
	for _, a := range auths {
		if a.Name() == "password" {
			pw = a
		}
	}
	if pw == nil {
		t.Fatal("password authenticator not registered")
	}

	// Correct password authenticates the runtime user.
	res, err := pw.Authenticate(ctx, &sso.AuthRequest{
		Credential: map[string]string{"username": "root", "password": "Sup3rSecret!"},
	})
	if err != nil {
		t.Fatalf("runtime store user could not authenticate: %v", err)
	}
	if res.UserID != "root" {
		t.Errorf("UserID = %q, want root", res.UserID)
	}

	// Wrong password and unknown user both fail (anti-enumeration: one error).
	if _, err := pw.Authenticate(ctx, &sso.AuthRequest{
		Credential: map[string]string{"username": "root", "password": "wrong"},
	}); err == nil {
		t.Error("wrong password must fail")
	}
	if _, err := pw.Authenticate(ctx, &sso.AuthRequest{
		Credential: map[string]string{"username": "ghost", "password": "Sup3rSecret!"},
	}); err == nil {
		t.Error("unknown user must fail")
	}
}
