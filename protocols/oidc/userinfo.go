package oidc

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
	// Attributes win when both an attribute AND a first-class field
	// carry the same claim — the authenticator is the live source of
	// truth (User.Email + User.Name are caches that aren't always
	// repopulated by the login upsert path).
	emailFrom := func() string {
		if v, ok := u.Attributes["email"]; ok && v != "" {
			return v
		}
		return u.Email
	}
	nameFrom := func() string {
		if v, ok := u.Attributes["name"]; ok && v != "" {
			return v
		}
		return u.Name
	}
	if hasScope("email") {
		if v := emailFrom(); v != "" {
			out["email"] = v
		}
		if v, ok := u.Attributes["email_verified"]; ok {
			out["email_verified"] = v == "true"
		}
	}
	if hasScope("profile") {
		if v := nameFrom(); v != "" {
			out["name"] = v
		}
		for _, k := range []string{"given_name", "family_name", "picture", "preferred_username", "nickname", "locale", "zoneinfo"} {
			if v, ok := u.Attributes[k]; ok && v != "" {
				out[k] = v
			}
		}
	}
	if hasScope("address") {
		if v, ok := u.Attributes["address"]; ok && v != "" {
			out["address"] = v
		}
	}
	if hasScope("phone") {
		if v, ok := u.Attributes["phone_number"]; ok && v != "" {
			out["phone_number"] = v
		}
		if v, ok := u.Attributes["phone_number_verified"]; ok {
			out["phone_number_verified"] = v == "true"
		}
	}
	// OIDC Core §5.5: project userinfo-section requested claims that
	// scope alone did not already include. Fail-open on parse errors.
	if len(requestedClaims) > 0 {
		if _, userinfoReq, parseErr := core.ParseRequestedClaims(requestedClaims); parseErr == nil {
			for claimName := range userinfoReq {
				if _, alreadySet := out[claimName]; alreadySet {
					continue
				}
				if v, ok := u.Attributes[claimName]; ok && v != "" {
					out[claimName] = v
				}
			}
		}
	}
	return out
}
