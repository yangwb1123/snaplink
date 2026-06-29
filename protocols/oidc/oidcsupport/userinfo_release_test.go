package oidcsupport

import (
	"encoding/json"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// TestProjectRequestedClaims_DefaultDeny is the credential-leak regression guard
// for the OIDC §5.5 `claims` request parameter: it is DEFAULT-DENY, surfacing
// only releasable standard OIDC claims from User.Attributes. Credential/internal
// keys (password_hash, seeded_password, krb5_*, scim:*) AND deployment-custom
// keys are NOT released by name (custom release would need explicit operator
// config, never a default-allow that could leak a misnamed secret).
func TestProjectRequestedClaims_DefaultDeny(t *testing.T) {
	t.Parallel()
	u := &core.User{
		ID: "alice",
		Attributes: map[string]string{
			"seeded_password": "hunter2-plaintext",
			"password_hash":   "$2a$10$deadbeef",
			"krb5_realm":      "CORP.EXAMPLE",
			"scim:active":     "true",
			"keytab":          "BASE64KEYTAB", // a backend secret NOT name-matchable
			"nickname":        "Al",           // standard OIDC claim
			"team":            "platform",     // deployment-custom claim
		},
	}
	requested := json.RawMessage(`{"userinfo":{"seeded_password":null,"password_hash":null,"krb5_realm":null,"scim:active":null,"keytab":null,"nickname":null,"team":null}}`)
	out := ProjectUserInfoForOIDC(u, []string{"openid"}, requested)

	for _, blocked := range []string{"seeded_password", "password_hash", "krb5_realm", "scim:active", "keytab", "team"} {
		if _, present := out[blocked]; present {
			t.Fatalf("non-standard key %q released via claims param (default-deny breached): %v", blocked, out[blocked])
		}
	}
	if out["nickname"] != "Al" {
		t.Errorf("releasable standard claim nickname not surfaced: %v", out["nickname"])
	}
	if out["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", out["sub"])
	}
}

// TestSanitizeUserForUserInfo filters the non-OIDC /userinfo response Attributes
// to the standard-claim allowlist (default-deny), so credential/internal keys
// (incl. the bootstrap admin's plaintext seeded_password and unpredictably-named
// backend secrets like keytab) never leak, while standard claims survive. The
// source user is never mutated.
func TestSanitizeUserForUserInfo(t *testing.T) {
	t.Parallel()
	u := &core.User{
		ID:   "bob",
		Name: "Bob",
		Attributes: map[string]string{
			"seeded_password": "generated-plaintext-pw",
			"password_hash":   "$2a$10$secret",
			"krb5_realm":      "CORP",
			"radius_class":    "vip",
			"keytab":          "BASE64KEYTAB",
			"scim:active":     "true",
			"team":            "platform", // custom -> dropped under default-deny
			"email":           "bob@example.com",
			"nickname":        "Bobby",
		},
	}
	clean := SanitizeUserForUserInfo(u)
	for _, blocked := range []string{"seeded_password", "password_hash", "krb5_realm", "radius_class", "keytab", "scim:active", "team"} {
		if _, present := clean.Attributes[blocked]; present {
			t.Errorf("non-standard key %q survived sanitization (default-deny breached)", blocked)
		}
	}
	if clean.Attributes["email"] != "bob@example.com" {
		t.Errorf("releasable standard claim email wrongly stripped: %v", clean.Attributes["email"])
	}
	if clean.Attributes["nickname"] != "Bobby" {
		t.Errorf("releasable standard claim nickname wrongly stripped: %v", clean.Attributes["nickname"])
	}
	if _, ok := u.Attributes["seeded_password"]; !ok {
		t.Errorf("sanitization mutated the source user's Attributes")
	}
}
