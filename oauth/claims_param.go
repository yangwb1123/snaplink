package oauth

import (
	"encoding/json"
	"errors"
)

// ClaimRequest holds the optional constraints from one entry inside
// the OIDC Core §5.5 `claims` parameter object. A nil *ClaimRequest
// means "just include the claim" (JSON null entry).
type ClaimRequest struct {
	// Essential signals the RP considers this claim indispensable; the
	// AS SHOULD treat a failure to provide it as an error.
	Essential bool
	// Value is a single acceptable value constraint (raw JSON). nil = unconstrained.
	Value json.RawMessage
	// Values is a multi-value acceptable constraint (raw JSON elements). nil = unconstrained.
	Values []json.RawMessage
}

// ParseRequestedClaims parses the validated claims parameter into its
// userinfo and id_token sections. Returns nil maps when a section is absent.
// The outer map key is the claim name; the inner *ClaimRequest is nil for
// "just include this claim" (JSON null) or a populated spec for constrained
// requests.
func ParseRequestedClaims(raw json.RawMessage) (idToken map[string]*ClaimRequest, userinfo map[string]*ClaimRequest, err error) {
	if len(raw) == 0 {
		return nil, nil, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, nil, errors.New("claims: must be a JSON object")
	}
	idToken, err = parseClaimsSection(obj["id_token"])
	if err != nil {
		return nil, nil, err
	}
	userinfo, err = parseClaimsSection(obj["userinfo"])
	if err != nil {
		return nil, nil, err
	}
	return idToken, userinfo, nil
}

// parseClaimsSection parses one section (id_token or userinfo) of the claims
// parameter into a map of claim name → *ClaimRequest.
func parseClaimsSection(raw json.RawMessage) (map[string]*ClaimRequest, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(raw, &inner); err != nil {
		return nil, errors.New("claims: section must be a JSON object")
	}
	if len(inner) == 0 {
		return nil, nil
	}
	out := make(map[string]*ClaimRequest, len(inner))
	for name, spec := range inner {
		if len(spec) == 0 || string(spec) == "null" {
			out[name] = nil
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(spec, &obj); err != nil {
			return nil, errors.New("claims: entry for " + name + " must be null or an object")
		}
		cr := &ClaimRequest{}
		if v, ok := obj["essential"]; ok && len(v) > 0 {
			if err := json.Unmarshal(v, &cr.Essential); err != nil {
				return nil, errors.New("claims: " + name + ".essential must be a boolean")
			}
		}
		if v, ok := obj["value"]; ok && len(v) > 0 {
			cr.Value = append(json.RawMessage(nil), v...)
		}
		if v, ok := obj["values"]; ok && len(v) > 0 {
			var arr []json.RawMessage
			if err := json.Unmarshal(v, &arr); err != nil {
				return nil, errors.New("claims: " + name + ".values must be an array")
			}
			cr.Values = arr
		}
		out[name] = cr
	}
	return out, nil
}

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
