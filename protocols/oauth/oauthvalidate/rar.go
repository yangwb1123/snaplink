package oauthvalidate

import (
	"encoding/json"
	"errors"
	"slices"

	"github.com/snaplink/sso/shared/core"
)

// RFC 9396 — Rich Authorization Requests.
//
// Lets a relying party request fine-grained authorization beyond
// what scopes can express. Canonical use cases: Open Banking
// payment authorization ("transfer 500 EUR to IBAN X"), healthcare
// consent ("read patient records for case Y"), per-resource
// permissions ("write to document Z but not delete it").
//
// On the wire, `authorization_details` is a JSON array where each
// element is an object with a REQUIRED `type` field plus
// arbitrary other fields specific to that type. We preserve the
// raw JSON via json.RawMessage so type-specific extensions don't
// need to model their schema in this SDK — they pass through
// unmodified from the authorization request into the issued
// access token's `authorization_details` claim.

// KeyAuthorizationDetails is the wire key for the RFC 9396
// parameter on /auth/login and the claim of the same name on
// issued access tokens.
const KeyAuthorizationDetails = "authorization_details"

// ErrInvalidAuthorizationDetails is the sentinel returned to the
// client when authorization_details parsing fails or contains a
// type outside the client's allowlist. Wire code maps to
// invalid_authorization_details per RFC 9396 §6.
const ErrInvalidAuthorizationDetails = "invalid_authorization_details"

// authorizationDetail is the minimal shape every element MUST
// satisfy: a non-empty `type` field. The remaining fields are
// type-specific and pass through unparsed.
type authorizationDetail struct {
	Type string `json:"type"`
}

// CloneRawJSON returns a copy of the raw JSON bytes — guards
// against aliasing when storing authorization_details across
// request-scoped and persistence-scoped lifetimes. Nil-safe.
func CloneRawJSON(raw json.RawMessage) json.RawMessage {
	return core.CloneRawJSON(raw)
}

// ValidateAuthorizationDetails parses the raw JSON, asserts it's
// a JSON array, asserts every element has a non-empty `type`
// field, and (when allowed is non-empty) verifies every element's
// type appears in the allowlist. Returns the parsed element list
// for downstream introspection; the original raw JSON is what
// gets persisted + stamped (preserves extension fields verbatim).
//
// Empty input (zero-length RawMessage) → (nil, nil): nothing to
// validate, nothing to enforce. Callers use the parsed return
// value only for type-checking against the allowlist; payload
// stamping reuses the raw JSON directly.
func ValidateAuthorizationDetails(raw json.RawMessage, allowed []string) ([]authorizationDetail, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var details []authorizationDetail
	if err := json.Unmarshal(raw, &details); err != nil {
		return nil, errors.New("authorization_details: invalid JSON or not an array")
	}
	for _, d := range details {
		if d.Type == "" {
			return nil, errors.New("authorization_details: element missing required `type` field")
		}
		if len(allowed) > 0 && !slices.Contains(allowed, d.Type) {
			return nil, errors.New("authorization_details: type not in client allowlist")
		}
	}
	return details, nil
}
