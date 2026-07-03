package sso_test

// rootcov_admin_token_policies_test.go covers GET /api/v1/admin/token-policies
// — the read-only token-policy governance view backing WithTokenPolicy — sat
// behind the same AdminMiddleware gate as every other /api/v1/admin/* route.

import (
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/domains/tokenpolicy/memory"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestRcovAdmin_TokenPoliciesNotMountedWithoutStore proves the byte-identical
// default: without WithTokenPolicy the route is genuinely unmounted (404), not
// merely unauthorized — even for a fully-authorized admin bearer.
func TestRcovAdmin_TokenPoliciesNotMountedWithoutStore(t *testing.T) {
	t.Parallel()
	env := rcovNewAdminServer(t)
	status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/token-policies", env.token, nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET /api/v1/admin/token-policies without a store = %d, want 404", status)
	}
}

// TestRcovAdmin_TokenPoliciesRequiresAdminBearer proves the endpoint sits
// behind the AdminMiddleware gate: no bearer → 401.
func TestRcovAdmin_TokenPoliciesRequiresAdminBearer(t *testing.T) {
	t.Parallel()
	store := memory.New(tokenpolicy.Policy{Name: "p", MaxTTL: time.Minute})
	env := rcovNewAdminServer(t, sso.WithTokenPolicy(store))

	status, _ := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/token-policies", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("no-bearer token-policies view = %d, want 401", status)
	}
}

// TestRcovAdmin_TokenPoliciesInventory proves the endpoint returns the active
// governance rule set — selectors + numeric limits, no secret material.
func TestRcovAdmin_TokenPoliciesInventory(t *testing.T) {
	t.Parallel()
	store := memory.New(
		tokenpolicy.Policy{Name: "short-ttl", ClientID: "payments", MaxTTL: 5 * time.Minute},
		tokenpolicy.Policy{Name: "no-admin-openid", BlockScopeCombos: [][]string{{"admin:*", "openid"}}},
	)
	env := rcovNewAdminServer(t, sso.WithTokenPolicy(store))

	status, out := rcovDo(t, http.MethodGet, env.url+"/api/v1/admin/token-policies", env.token, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/token-policies = %d body=%v", status, out)
	}
	policies, _ := out["policies"].([]any)
	if len(policies) != 2 {
		t.Fatalf("policies = %d entries, want 2 (body=%v)", len(policies), out)
	}
	first, _ := policies[0].(map[string]any)
	if first["name"] != "short-ttl" || first["client_id"] != "payments" {
		t.Errorf("policy[0] = %v, want short-ttl/payments", first)
	}
}
