package sso

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

// validateClaimsParameter asserts the raw JSON is a JSON object
// (the only shape OIDC Core §5.5 defines). Detailed per-claim
// validation is deferred to consumers — extension members are
// explicitly allowed by the spec, and a strict schema here would
// reject perfectly valid forward-compatible payloads.
func validateClaimsParameter(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return errors.New("claims: must be a JSON object")
	}
	// Per §5.5, top-level "userinfo" and "id_token" entries (when
	// present) MUST themselves be JSON objects. Other top-level
	// keys are unspecified by the spec — we accept them quietly so
	// future-extension RPs aren't broken.
	for _, key := range []string{"userinfo", "id_token"} {
		raw, ok := obj[key]
		if !ok || len(raw) == 0 {
			continue
		}
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(raw, &inner); err != nil {
			return errors.New("claims: \"" + key + "\" must be a JSON object")
		}
	}
	return nil
}
