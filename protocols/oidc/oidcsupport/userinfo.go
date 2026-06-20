package oidcsupport

import (
	"encoding/json"
	"slices"

	"github.com/snaplink/sso/shared/core"
)

// ProjectUserInfoForOIDC returns the OIDC-standard claim set for a user
// gated by the token's scopes. OIDC Core §5.4 mapping:
//
//	openid  → sub (always)
//	email   → email, email_verified
//	profile → name, given_name, family_name, picture, preferred_username
//	address → address (object)
//	phone   → phone_number, phone_number_verified
//
// Non-standard fields on the User (provider, external_id, created_at,
// updated_at) are omitted — OIDC RPs don't expect them and including
// them would make the response shape ambiguous with the legacy
// non-OIDC response.
//
// Per-claim values come from User's first-class fields (Email, Name)
// or from Attributes when the field name matches the claim name.
// Operators control which claims are exposed via what they populate
// in the User and Attributes — there's no per-server claim allowlist
// to maintain.
func ProjectUserInfoForOIDC(u *core.User, scopes []string, requestedClaims json.RawMessage) map[string]any {
	out := map[string]any{"sub": u.ID}
	hasScope := func(name string) bool {
		return slices.Contains(scopes, name)
	}
	if hasScope("email") {
		projectEmailClaims(out, u)
	}
	if hasScope("profile") {
		projectProfileClaims(out, u)
	}
	if hasScope("address") {
		projectAddressClaims(out, u)
	}
	if hasScope("phone") {
		projectPhoneClaims(out, u)
	}
	projectRequestedClaims(out, u, requestedClaims)
	return out
}

// projectEmailClaims projects the OIDC `email` scope claims onto out.
func projectEmailClaims(out map[string]any, u *core.User) {
	// Attributes win when both an attribute AND a first-class field
	// carry the same claim — the authenticator is the live source of
	// truth (User.Email is a cache that isn't always repopulated by the
	// login upsert path).
	emailFrom := func() string {
		if v, ok := u.Attributes["email"]; ok && v != "" {
			return v
		}
		return u.Email
	}
	if v := emailFrom(); v != "" {
		out["email"] = v
	}
	if v, ok := u.Attributes["email_verified"]; ok {
		out["email_verified"] = v == "true"
	}
}

// projectProfileClaims projects the OIDC `profile` scope claims onto out.
func projectProfileClaims(out map[string]any, u *core.User) {
	// Attributes win over the User.Name cache — same source-of-truth
	// rationale as the email claim.
	nameFrom := func() string {
		if v, ok := u.Attributes["name"]; ok && v != "" {
			return v
		}
		return u.Name
	}
	if v := nameFrom(); v != "" {
		out["name"] = v
	}
	for _, k := range []string{"given_name", "family_name", "picture", "preferred_username", "nickname", "locale", "zoneinfo"} {
		if v, ok := u.Attributes[k]; ok && v != "" {
			out[k] = v
		}
	}
}

// projectAddressClaims projects the OIDC `address` scope claim onto out.
func projectAddressClaims(out map[string]any, u *core.User) {
	if v, ok := u.Attributes["address"]; ok && v != "" {
		out["address"] = v
	}
}

// projectPhoneClaims projects the OIDC `phone` scope claims onto out.
func projectPhoneClaims(out map[string]any, u *core.User) {
	if v, ok := u.Attributes["phone_number"]; ok && v != "" {
		out["phone_number"] = v
	}
	if v, ok := u.Attributes["phone_number_verified"]; ok {
		out["phone_number_verified"] = v == "true"
	}
}

// projectRequestedClaims projects OIDC Core §5.5 userinfo-section requested
// claims that scope alone did not already include. Fail-open on parse errors.
func projectRequestedClaims(out map[string]any, u *core.User, requestedClaims json.RawMessage) {
	if len(requestedClaims) == 0 {
		return
	}
	_, userinfoReq, parseErr := core.ParseRequestedClaims(requestedClaims)
	if parseErr != nil {
		return
	}
	for claimName := range userinfoReq {
		if _, alreadySet := out[claimName]; alreadySet {
			continue
		}
		if v, ok := u.Attributes[claimName]; ok && v != "" {
			out[claimName] = v
		}
	}
}
