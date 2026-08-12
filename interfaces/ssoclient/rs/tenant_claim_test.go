package rs_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
)

// TestValidateToken_TenantIDProjection is the T-8(a) parse pin: the B4-1
// mint-time `tenant_id` claim (the client binding, stamped by every grant)
// must project onto Claims.TenantID on the JWT validation path — present
// claim populates, absent claim decodes to the zero value, and Raw always
// keeps the full document. There is deliberately NO rs.Config gate on the
// tenant claim: the tenant expectation is per-binding adapter config.
func TestValidateToken_TenantIDProjection(t *testing.T) {
	t.Parallel()
	iss := newTestIssuer(t)
	mint := func(tenantID string) string {
		t.Helper()
		claims := map[string]any{"sub": "user-1", "aud": "api://orders", "client_id": "client-1"}
		if tenantID != "" {
			claims["tenant_id"] = tenantID
		}
		tok, err := iss.MintAccessToken(claims)
		if err != nil {
			t.Fatalf("MintAccessToken: %v", err)
		}
		return tok
	}
	cfg := newTestConfig(t, iss, "api://orders")

	// Present claim -> typed projection + presence helper.
	claims, err := rs.ValidateToken(context.Background(), mint("tenant-one"), cfg)
	if err != nil {
		t.Fatalf("ValidateToken(tenant_id present): %v", err)
	}
	if claims.TenantID != "tenant-one" || !claims.HasTenantID() {
		t.Errorf("TenantID = %q, HasTenantID = %v, want tenant-one/true", claims.TenantID, claims.HasTenantID())
	}
	if got, ok := claims.Raw["tenant_id"].(string); !ok || got != "tenant-one" {
		t.Errorf("Raw[tenant_id] = %v, want the claim preserved in Raw", claims.Raw["tenant_id"])
	}

	// Absent claim -> zero value, no presence.
	claims, err = rs.ValidateToken(context.Background(), mint(""), cfg)
	if err != nil {
		t.Fatalf("ValidateToken(tenant_id absent): %v", err)
	}
	if claims.TenantID != "" || claims.HasTenantID() {
		t.Errorf("TenantID = %q, HasTenantID = %v, want empty/false", claims.TenantID, claims.HasTenantID())
	}
	if _, present := claims.Raw["tenant_id"]; present {
		t.Error("Raw[tenant_id] present on a claim-less token")
	}
}

// TestValidateTokenWithIntrospect_TenantID is the T-8(a) introspection-path
// pin: wireIntrospection embeds wireClaims, so a response carrying
// tenant_id decodes into Claims.TenantID automatically — but the projection
// literal in ValidateTokenWithIntrospect is field-by-field, so this test
// also proves the constructor copies the field (the embed alone would
// silently drop it).
func TestValidateTokenWithIntrospect_TenantID(t *testing.T) {
	t.Parallel()
	mk := func(tenantID string) rs.Config {
		t.Helper()
		resp := map[string]any{
			"active": true,
			"iss":    "https://as.test",
			"sub":    "user-1",
			"aud":    "api://orders",
			"scope":  "orders:read",
			"exp":    9999999999,
		}
		if tenantID != "" {
			resp["tenant_id"] = tenantID
		}
		srv := introspectServer(t, "rs-client", "rs-secret", resp)
		return rs.Config{
			Issuer:          "https://as.test",
			ExpectedAud:     "api://orders",
			IntrospectURL:   srv.URL,
			IntrospectCreds: &rs.ClientCreds{ID: "rs-client", Secret: "rs-secret"},
		}
	}

	claims, err := rs.ValidateTokenWithIntrospect(context.Background(), "opaque-token", mk("tenant-one"))
	if err != nil {
		t.Fatalf("ValidateTokenWithIntrospect(tenant_id present): %v", err)
	}
	if claims.TenantID != "tenant-one" || !claims.HasTenantID() {
		t.Errorf("TenantID = %q, HasTenantID = %v, want tenant-one/true", claims.TenantID, claims.HasTenantID())
	}

	claims, err = rs.ValidateTokenWithIntrospect(context.Background(), "opaque-token", mk(""))
	if err != nil {
		t.Fatalf("ValidateTokenWithIntrospect(tenant_id absent): %v", err)
	}
	if claims.TenantID != "" || claims.HasTenantID() {
		t.Errorf("TenantID = %q, HasTenantID = %v, want empty/false", claims.TenantID, claims.HasTenantID())
	}
}
