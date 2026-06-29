package oidcsupport

import (
	"encoding/json"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// TestProjectRequestedClaims_DefaultDeny is the credential-leak regression
// guard: the OIDC §5.5 `claims` request parameter must NOT surface arbitrary
// User.Attributes keys. A request for password_hash / scim:* must be ignored
// (default-deny allowlist), while a standard OIDC claim name is still surfaced.
func TestProjectRequestedClaims_DefaultDeny(t *testing.T) {
	u := &core.User{
		ID: "alice",
		Attributes: map[string]string{
			"password_hash":        "$2a$10$deadbeef",
			"password_hash_format": "bcrypt",
			"scim:active":          "true",
			"nickname":             "Al",
		},
	}
	// Token has only openid (no profile/email), and the claims param requests the
	// credential keys plus a standard claim by name.
	requested := json.RawMessage(`{"userinfo":{"password_hash":null,"password_hash_format":null,"scim:active":null,"nickname":null}}`)
	out := ProjectUserInfoForOIDC(u, []string{"openid"}, requested)

	if _, leaked := out["password_hash"]; leaked {
		t.Fatalf("password_hash leaked via claims param: %v", out["password_hash"])
	}
	if _, leaked := out["password_hash_format"]; leaked {
		t.Errorf("password_hash_format leaked via claims param")
	}
	if _, leaked := out["scim:active"]; leaked {
		t.Errorf("scim: internal key leaked via claims param")
	}
	// A standard OIDC claim requested by name is still honored.
	if out["nickname"] != "Al" {
		t.Errorf("allowlisted standard claim nickname not surfaced: %v", out["nickname"])
	}
	if out["sub"] != "alice" {
		t.Errorf("sub = %v, want alice", out["sub"])
	}
}

// TestSanitizeUserForUserInfo strips credential / internal attributes from the
// non-OIDC /userinfo response and never mutates the source user.
func TestSanitizeUserForUserInfo(t *testing.T) {
	u := &core.User{
		ID:   "bob",
		Name: "Bob",
		Attributes: map[string]string{
			"password_hash":        "$2a$10$secret",
			"password_hash_format": "bcrypt",
			"scim:active":          "true",
			"email":                "bob@example.com",
		},
	}
	clean := SanitizeUserForUserInfo(u)
	if _, leaked := clean.Attributes["password_hash"]; leaked {
		t.Fatalf("password_hash survived sanitization")
	}
	if _, leaked := clean.Attributes["password_hash_format"]; leaked {
		t.Errorf("password_hash_format survived sanitization")
	}
	if _, leaked := clean.Attributes["scim:active"]; leaked {
		t.Errorf("scim: key survived sanitization")
	}
	if clean.Attributes["email"] != "bob@example.com" {
		t.Errorf("non-sensitive attribute wrongly stripped: %v", clean.Attributes["email"])
	}
	// Source user must be untouched (shallow copy).
	if _, ok := u.Attributes["password_hash"]; !ok {
		t.Errorf("sanitization mutated the source user's Attributes")
	}
}
