package sso_test

// rootcov_token_policy_test.go drives the token-policy engine through the REAL
// /token issuance path (WithTokenPolicy): the ClampingIssuer's max_ttl clamp
// and the dispatch gate's block_scope_combos deny, plus the byte-identical
// default when no policy is wired.

import (
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/domains/tokenpolicy/memory"
	"github.com/snaplink/sso/interfaces/sso"
)

// TestRcov_TokenPolicy_ScopeComboDenied proves a forbidden scope combination is
// rejected at /token with the ORACLE-SAFE generic invalid_scope — the specific
// reason never reaches the wire.
func TestRcov_TokenPolicy_ScopeComboDenied(t *testing.T) {
	t.Parallel()
	store := memory.New(tokenpolicy.Policy{
		Name:             "no-admin-openid",
		BlockScopeCombos: [][]string{{"admin:*", "openid"}},
	})
	s := rcovNewServer(t, sso.WithTokenPolicy(store))

	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"scope":         "admin:read openid",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("forbidden combo status=%d body=%v, want 400", status, out)
	}
	if out["error"] != "invalid_scope" {
		t.Fatalf("error = %v, want invalid_scope (oracle-safe generic)", out["error"])
	}
}

// TestRcov_TokenPolicy_SafeScopesAllowed proves a request that does NOT trip a
// combo still mints normally under the same policy.
func TestRcov_TokenPolicy_SafeScopesAllowed(t *testing.T) {
	t.Parallel()
	store := memory.New(tokenpolicy.Policy{
		Name:             "no-admin-openid",
		BlockScopeCombos: [][]string{{"admin:*", "openid"}},
	})
	s := rcovNewServer(t, sso.WithTokenPolicy(store))

	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"scope":         "read",
	})
	if status != http.StatusOK {
		t.Fatalf("safe-scope status=%d body=%v, want 200", status, tok)
	}
	if tok["access_token"] == nil || tok["access_token"] == "" {
		t.Fatalf("no access_token: %v", tok)
	}
}

// TestRcov_TokenPolicy_MaxTTLClampsIssuedToken proves max_ttl clamps the issued
// access token's lifetime downward, uniformly, via the ClampingIssuer on the
// real issuance path. The base server's issuer default is 1m; a 15s ceiling
// (with the client's AccessTokenTTL unset) yields expires_in == 15.
func TestRcov_TokenPolicy_MaxTTLClampsIssuedToken(t *testing.T) {
	t.Parallel()
	store := memory.New(tokenpolicy.Policy{Name: "short", MaxTTL: 15 * time.Second})
	s := rcovNewServer(t, sso.WithTokenPolicy(store))

	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"scope":         "read",
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, tok)
	}
	expiresIn, _ := tok["expires_in"].(float64)
	if int(expiresIn) != 15 {
		t.Fatalf("expires_in = %v, want 15 (clamped from the 1m issuer default)", tok["expires_in"])
	}
}

// TestRcov_TokenPolicy_UnwiredIsByteIdentical proves the default: with no
// policy store the same request mints at the issuer default lifetime (1m).
func TestRcov_TokenPolicy_UnwiredIsByteIdentical(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"scope":         "read",
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, tok)
	}
	expiresIn, _ := tok["expires_in"].(float64)
	if int(expiresIn) != 60 {
		t.Fatalf("expires_in = %v, want 60 (unclamped issuer default)", tok["expires_in"])
	}
}
