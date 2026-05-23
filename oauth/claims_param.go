package oauth

import (
	"encoding/json"
	"errors"
)

// OIDC Core §5.5 — the `claims` request parameter.
//
// Lets the RP request specific claims for inclusion in the
// id_token / userinfo response, optionally marking some as
// essential. Shape:
//
//	{
//	  "userinfo": {
//	    "email":          null,
//	    "name":           {"essential": true},
//	    "given_name":     {"essential": true, "value": "Alice"}
//	  },
//	  "id_token": {
//	    "acr": {"values": ["urn:mace:incommon:iap:silver"]}
//	  }
//	}
//
// Top-level keys are "userinfo" and "id_token"; each value is a
// JSON object whose keys name the requested claims, with `null`
// (just request) or a request specification object as the value.
//
// This server preserves the raw JSON and forwards it to authenticators
// + issuers via AuthRequest.RequestedClaims; implementations that
// honor it project the claims into their output. Implementations
// that don't simply pass the field through — empty `claims` is a
// safe no-op.

// ValidateClaimsParameter asserts the raw JSON is a JSON object
// (the only shape OIDC Core §5.5 defines) AND that each requested-
// claim entry is either null OR a JSON object whose well-known
// members (essential / value / values) carry the spec-mandated
// types. Catching shape errors here means RP misconfiguration
// surfaces as invalid_request at /auth/login rather than silently
// dropping through to "your essential claim was ignored" — the
// latter is the bug RPs spend hours debugging.
//
// Extension members of the per-claim object are explicitly allowed
// by §5.5 and skipped here — strict-typing them would reject
// forward-compatible payloads.
func ValidateClaimsParameter(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return errors.New("claims: must be a JSON object")
	}
	for _, top := range []string{"userinfo", "id_token"} {
		section, ok := obj[top]
		if !ok || len(section) == 0 {
			continue
		}
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(section, &inner); err != nil {
			return errors.New("claims: \"" + top + "\" must be a JSON object")
		}
		for claim, spec := range inner {
			if err := validateClaimRequestSpec(top, claim, spec); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateClaimRequestSpec checks one entry inside `userinfo` or
// `id_token`. Per OIDC Core §5.5.1, the value is either JSON null
// (request the claim, no extra constraints) or a JSON object with
// optional `essential` (bool), `value` (any single value), `values`
// (array). Wrong types → invalid_request; this gives RPs a clear
// signal that their {"essential": "yes"} typo isn't silently
// downgraded to non-essential.
func validateClaimRequestSpec(top, claim string, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return errors.New("claims: \"" + top + "." + claim + "\" must be null or an object")
	}
	if v, ok := obj["essential"]; ok && len(v) > 0 {
		// json.Unmarshal of a non-bool into *bool returns an error
		// — that's exactly the shape signal we want.
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return errors.New("claims: \"" + top + "." + claim + ".essential\" must be a boolean")
		}
	}
	if v, ok := obj["values"]; ok && len(v) > 0 {
		var arr []json.RawMessage
		if err := json.Unmarshal(v, &arr); err != nil {
			return errors.New("claims: \"" + top + "." + claim + ".values\" must be an array")
		}
	}
	// `value` accepts any JSON primitive per §5.5.1 — no shape check
	// beyond well-formed JSON, which the outer Unmarshal already
	// verified. Extension fields are ignored.
	return nil
}
