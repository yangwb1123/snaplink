package sso_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestConditionalAccess_EnforcesRoleMembership(t *testing.T) {
	ctx := context.Background()
	roles := permissions.NewMemoryProvider()
	if err := roles.AddRole(ctx, rcovClient, permissions.Role{Code: "admin"}); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if err := roles.AssignRoles(ctx, rcovUser, rcovClient, []string{"admin"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	policies := conditionalaccess.NewMemoryStore()
	policy := conditionalaccess.Policy{
		Name: "deny-admin", Priority: 100, Enabled: true,
		Conditions: conditionalaccess.Conditions{UserMemberOf: []string{"admin"}},
		Actions:    conditionalaccess.Actions{Deny: true},
	}
	if err := policies.Put(ctx, policy); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithPermissionProvider(roles),
		sso.WithConditionalAccess(policies, conditionalaccess.Config{Enforce: true}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusForbidden || out["error"] != "conditional_access_denied" {
		t.Fatalf("role policy status=%d body=%v, want 403 conditional_access_denied", status, out)
	}
}

func TestConditionalAccess_RolePolicyDoesNotMatchUnassignedUser(t *testing.T) {
	ctx := context.Background()
	roles := permissions.NewMemoryProvider()
	if err := roles.AddRole(ctx, rcovClient, permissions.Role{Code: "admin"}); err != nil {
		t.Fatalf("add role: %v", err)
	}
	policies := conditionalaccess.NewMemoryStore()
	if err := policies.Put(ctx, conditionalaccess.Policy{
		Name: "deny-admin", Priority: 100, Enabled: true,
		Conditions: conditionalaccess.Conditions{UserMemberOf: []string{"admin"}},
		Actions:    conditionalaccess.Actions{Deny: true},
	}); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	s := rcovNewServer(t, sso.WithPermissionProvider(roles),
		sso.WithConditionalAccess(policies, conditionalaccess.Config{Enforce: true}))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	if status != http.StatusOK || out["access_token"] == nil {
		t.Fatalf("unassigned role policy status=%d body=%v, want successful login", status, out)
	}
}

func TestConditionalAccess_RunsAfterRiskMFAResume(t *testing.T) {
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(context.Background(), denyAllPolicy()); err != nil {
		t.Fatal(err)
	}
	s := rcovNewServer(t,
		sso.WithRiskScorer(rcovRequireMFAScorer{}),
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
		sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}),
	)
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", capLoginBody())
	challengeID, _ := out["mfa_challenge_id"].(string)
	if status != http.StatusOK || challengeID == "" {
		t.Fatalf("risk leg status=%d body=%v, want MFA challenge", status, out)
	}
	status, out = rcovPostJSON(t, s.http.URL+"/auth/mfa", "", map[string]any{
		"mfa_challenge_id": challengeID, "mfa_method": "totp", "code": "123456",
	})
	if status != http.StatusForbidden || out["error"] != "conditional_access_denied" || out["access_token"] != nil {
		t.Fatalf("post-MFA CAP status=%d body=%v, want denial without token", status, out)
	}
}

func TestConditionalAccess_MFAResumeIntersectsUpdatedRestrictions(t *testing.T) {
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	policy := conditionalaccess.Policy{Name: "changing", Priority: 100, Enabled: true,
		Actions: conditionalaccess.Actions{RequireStepUp: "mfa", RestrictScopes: []string{"openid"}}}
	if err := store.Put(ctx, policy); err != nil {
		t.Fatal(err)
	}
	s := rcovNewServer(t,
		sso.WithMFAProvider(rcovTOTPProvider{}),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
		sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}),
	)
	body := capLoginBody()
	body["scope"] = []string{"openid", "profile"}
	_, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", body)
	challengeID, _ := out["mfa_challenge_id"].(string)
	if challengeID == "" {
		t.Fatalf("missing challenge: %v", out)
	}
	policy.Actions = conditionalaccess.Actions{Allow: true, RestrictScopes: []string{"profile"}}
	if err := store.Put(ctx, policy); err != nil {
		t.Fatal(err)
	}
	status, out := rcovPostJSON(t, s.http.URL+"/auth/mfa", "", map[string]any{
		"mfa_challenge_id": challengeID, "mfa_method": "totp", "code": "123456",
	})
	if status != http.StatusBadRequest || out["error"] != "invalid_scope" || out["access_token"] != nil {
		t.Fatalf("disjoint restrictions status=%d body=%v, want invalid_scope without token", status, out)
	}
}
