package sso_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestConditionalAccess_EnforcesSilentRenewal(t *testing.T) {
	tests := []struct {
		name       string
		actions    conditionalaccess.Actions
		wantStatus int
		wantError  string
		wantScope  string
	}{
		{name: "deny", actions: conditionalaccess.Actions{Deny: true}, wantStatus: http.StatusForbidden, wantError: "conditional_access_denied"},
		{name: "step up requires interaction", actions: conditionalaccess.Actions{RequireStepUp: "mfa"}, wantStatus: http.StatusBadRequest, wantError: "interaction_required"},
		{name: "restrict scopes", actions: conditionalaccess.Actions{RestrictScopes: []string{"openid"}}, wantStatus: http.StatusOK, wantScope: "openid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := conditionalaccess.NewMemoryStore()
			issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
			s := rcovNewServer(t,
				sso.WithTokenIssuer("jwt", issuer), sso.WithIDTokenIssuer(issuer),
				sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}),
			)
			hint := seedSilentRenewalHint(t, s)
			policy := conditionalaccess.Policy{Name: "silent-policy", Priority: 100, Enabled: true, Actions: test.actions}
			if err := store.Put(context.Background(), policy); err != nil {
				t.Fatalf("put policy: %v", err)
			}
			status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
				"client_id": rcovClient, "prompt": "none", "scope": []string{"openid", "profile"}, "id_token_hint": hint,
			})
			if status != test.wantStatus || (test.wantError != "" && out["error"] != test.wantError) ||
				(test.wantScope != "" && out["scope"] != test.wantScope) {
				t.Fatalf("silent renewal status=%d body=%v, want status=%d error=%q scope=%q",
					status, out, test.wantStatus, test.wantError, test.wantScope)
			}
			if test.wantStatus != http.StatusOK && out["access_token"] != nil {
				t.Fatalf("denied silent renewal minted token: %v", out)
			}
		})
	}
}

func seedSilentRenewalHint(t *testing.T, s *rcovServer) string {
	t.Helper()
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider": "password", "client_id": rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile"},
	})
	hint, _ := out["id_token"].(string)
	if status != http.StatusOK || hint == "" {
		t.Fatalf("seed login status=%d body=%v", status, out)
	}
	return hint
}

func TestSilentRenewal_PreservesOriginalGrantWithoutInteraction(t *testing.T) {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rcovClient, Active: true, SkipConsent: true, TokenStrategy: "jwt",
		AllowedAuthenticators: []string{"password"},
		AllowedScopes:         []string{"openid", "profile", "email"},
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	s := rcovNewServer(t, sso.WithClientStore(clients), sso.WithTokenIssuer("jwt", issuer), sso.WithIDTokenIssuer(issuer))
	hint := seedSilentRenewalHint(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"client_id": rcovClient, "prompt": "none", "id_token_hint": hint,
	})
	if status != http.StatusOK || out["scope"] != "openid profile" {
		t.Fatalf("omitted-scope renewal status=%d body=%v, want original openid profile grant", status, out)
	}

	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"client_id": rcovClient, "prompt": "none", "scope": []string{"openid", "email"}, "id_token_hint": hint,
	})
	if status != http.StatusBadRequest || out["error"] != "consent_required" || out["access_token"] != nil {
		t.Fatalf("expanded-scope renewal status=%d body=%v, want 400 consent_required without token", status, out)
	}
}
