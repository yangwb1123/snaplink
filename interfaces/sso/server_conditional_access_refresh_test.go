package sso_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestConditionalAccess_RefreshReevaluatesLivePolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		policy     conditionalaccess.Policy
		wantStatus int
		wantError  string
		wantScope  string
	}{
		{"deny", denyAllPolicy(), http.StatusBadRequest, "invalid_grant", ""},
		{"step_up", stepUpAllPolicy(), http.StatusBadRequest, "insufficient_user_authentication", ""},
		{"restrict_scopes", restrictScopesAllPolicy(), http.StatusOK, "", "openid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := conditionalaccess.NewMemoryStore()
			env := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))
			_, refresh := rcovDirectLogin(t, env)
			if err := store.Put(context.Background(), tc.policy); err != nil {
				t.Fatalf("put policy after login: %v", err)
			}
			status, out := tpolRefresh(t, env, refresh)
			if status != tc.wantStatus || (tc.wantError != "" && out["error"] != tc.wantError) {
				t.Fatalf("refresh status=%d body=%v, want status=%d error=%q", status, out, tc.wantStatus, tc.wantError)
			}
			if tc.wantScope != "" && out["scope"] != tc.wantScope {
				t.Fatalf("refresh scope=%v, want %q", out["scope"], tc.wantScope)
			}
		})
	}
}

func TestConditionalAccess_RefreshFailsOpenOnStoreOutage(t *testing.T) {
	t.Parallel()
	env := rcovNewServer(t, sso.WithConditionalAccess(errCAPStore{}, conditionalaccess.Config{Enforce: true, DefaultDeny: true}))
	_, refresh := rcovDirectLogin(t, env)
	status, out := tpolRefresh(t, env, refresh)
	if status != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("refresh during CAP outage status=%d body=%v, want fail-open success", status, out)
	}
}

func TestConditionalAccess_RefreshEnforcesAuthenticationAge(t *testing.T) {
	t.Parallel()
	store := conditionalaccess.NewMemoryStore()
	env := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))
	_, refresh := rcovDirectLogin(t, env)
	info, err := env.refresh.Inspect(context.Background(), refresh)
	if err != nil {
		t.Fatalf("Inspect refresh: %v", err)
	}
	if err := env.refresh.Delete(context.Background(), refresh); err != nil {
		t.Fatalf("Delete refresh: %v", err)
	}
	info.AuthTime = time.Now().Add(-2 * time.Hour)
	if err := env.refresh.Issue(context.Background(), refresh, info); err != nil {
		t.Fatalf("reissue backdated refresh: %v", err)
	}
	policy := conditionalaccess.Policy{Name: "periodic-reauth", Enabled: true,
		Conditions: conditionalaccess.Conditions{AuthenticationAgeSeconds: 3600},
		Actions:    conditionalaccess.Actions{RequireStepUp: "mfa"}}
	if err := store.Put(context.Background(), policy); err != nil {
		t.Fatalf("put age policy: %v", err)
	}
	status, out := tpolRefresh(t, env, refresh)
	if status != http.StatusBadRequest || out["error"] != "insufficient_user_authentication" {
		t.Fatalf("old-auth refresh status=%d body=%v", status, out)
	}
}

func TestRefreshGrant_SessionStepUpMarkerForcesReauthentication(t *testing.T) {
	t.Parallel()
	env := rcovNewServer(t)
	access, refresh := rcovDirectLogin(t, env)
	claims, _, err := env.srv.ValidateAnyToken(context.Background(), access)
	if err != nil || claims.SID == "" {
		t.Fatalf("validate login access token / sid: claims=%+v err=%v", claims, err)
	}
	if err := env.sessions.MarkStepUp(context.Background(), claims.SID); err != nil {
		t.Fatalf("MarkStepUp: %v", err)
	}
	status, out := tpolRefresh(t, env, refresh)
	if status != http.StatusBadRequest || out["error"] != "insufficient_user_authentication" {
		t.Fatalf("marked-session refresh status=%d body=%v", status, out)
	}
}
