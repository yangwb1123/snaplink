package oauthvalidate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/shared/core"
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
	Type    string `json:"type"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Service string `json:"service"`
	Op      string `json:"op"`
	Field   string `json:"field"`
}

// RARLimits bounds an authorization_details payload's SHAPE before it is
// unmarshaled into typed values — a client can otherwise hand the server an
// arbitrarily large or deeply-nested JSON blob and force it to walk that
// structure (recursive descent + allocation) before the type-allowlist check
// in ValidateAuthorizationDetails ever runs. Every field's zero value
// disables that specific check (unbounded) — an unconfigured RARLimits{} is
// byte-identical to the behavior before this type existed.
//
// Composes with, rather than replaces, the generic whole-request
// SecurityConfig.BodyLimit: BodyLimit caps the entire HTTP body, RARLimits
// additionally caps the shape of just the authorization_details value once
// it's been bound out of that body.
type RARLimits struct {
	// MaxBytes caps the raw serialized size (len of the JSON value) of
	// authorization_details. 0 = unbounded.
	MaxBytes int
	// MaxElements caps the number of elements the top-level JSON array (or
	// direct children of a top-level object) may contain. 0 = unbounded.
	MaxElements int
	// MaxDepth caps the deepest nested object/array in the payload. 0 =
	// unbounded.
	MaxDepth int
}

// checkRARShape walks raw with a streaming token decoder — no intermediate
// Go values, no recursive descent — so its cost is bounded by
// min(len(raw), byte-offset of the first violating token) rather than by
// whatever size or nesting an attacker sends. It is called BEFORE
// ValidateAuthorizationDetails' json.Unmarshal so a hostile payload is
// rejected ahead of that more expensive walk.
//
// A malformed-JSON error from the decoder is swallowed (returns nil): the
// subsequent json.Unmarshal in ValidateAuthorizationDetails produces the
// authoritative "invalid JSON" error — this pass only enforces shape.
func checkRARShape(raw []byte, limits RARLimits) error {
	if limits.MaxBytes > 0 && len(raw) > limits.MaxBytes {
		return errors.New("authorization_details: exceeds maximum size")
	}
	if limits.MaxDepth <= 0 && limits.MaxElements <= 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	depth, topElements := 0, 0
	for {
		tok, err := dec.Token()
		if err != nil {
			// EOF (done, no violation found) and malformed JSON (Unmarshal
			// below reports the authoritative error) both fall through here.
			return nil
		}
		depth, topElements = advanceRARToken(tok, depth, topElements)
		if limits.MaxDepth > 0 && depth > limits.MaxDepth {
			return errors.New("authorization_details: exceeds maximum nesting depth")
		}
		if limits.MaxElements > 0 && topElements > limits.MaxElements {
			return errors.New("authorization_details: exceeds maximum element count")
		}
	}
}

// advanceRARToken folds one decoded JSON token into (depth, topElements).
// A scalar or a container-opening delim seen at depth==1 is a direct child
// of the top-level container — i.e. one RAR element — so it bumps
// topElements; a container-opening delim also increments depth, a closing
// one decrements it. Split out of checkRARShape to keep both functions well
// under the cyclomatic-complexity budget.
func advanceRARToken(tok json.Token, depth, topElements int) (int, int) {
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		if depth == 1 {
			topElements++
		}
		return depth, topElements
	}
	if delim == '[' || delim == '{' {
		if depth == 1 {
			topElements++
		}
		return depth + 1, topElements
	}
	return depth - 1, topElements
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
//
// limits is checked FIRST, via checkRARShape, before the json.Unmarshal
// below walks the payload into typed values — a zero-value RARLimits{}
// (the default when a caller has no configured limits) skips that pass
// entirely and this function behaves exactly as it did before limits
// existed.
func ValidateAuthorizationDetails(raw json.RawMessage, allowed []string, limits RARLimits) ([]authorizationDetail, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if err := checkRARShape(raw, limits); err != nil {
		return nil, err
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

// ValidateAuthorizationDetailsCatalog verifies the first-party resource
// types whose authorization_details fields identify a catalog resource. The
// caller maps every error to invalid_authorization_details; a catalog miss or
// store failure therefore fails closed before a PAR request is issued.
func ValidateAuthorizationDetailsCatalog(raw json.RawMessage, rp permissions.ResourceProvider, tenantID, clientID string) error {
	if len(raw) == 0 {
		return nil
	}
	if rp == nil {
		return errors.New("authorization_details: resource catalog unavailable")
	}
	details, err := ValidateAuthorizationDetails(raw, nil, RARLimits{})
	if err != nil {
		return err
	}
	for _, detail := range details {
		lookup, ok := detail.catalogLookup(tenantID, clientID)
		if !ok {
			continue
		}
		decision, err := rp.ResolveResource(context.Background(), lookup)
		if err != nil {
			return fmt.Errorf("authorization_details: resource catalog lookup failed: %w", err)
		}
		if decision == nil || !decision.Found {
			return fmt.Errorf("authorization_details: %s resource is not registered", detail.Type)
		}
	}
	return nil
}

func (d authorizationDetail) catalogLookup(tenantID, clientID string) (permissions.ResourceLookup, bool) {
	attrs, resourceType := d.catalogAttributes()
	if resourceType == "" {
		return permissions.ResourceLookup{}, false
	}
	return permissions.ResourceLookup{
		TenantID: tenantID,
		ClientID: clientID,
		Type:     permissions.ResourceType(resourceType),
		Match:    attrs,
	}, true
}

func (d authorizationDetail) catalogAttributes() (map[string]string, string) {
	switch d.Type {
	case string(permissions.ResourceTypeHTTPAPI):
		return map[string]string{"method": d.Method, "path": d.Path}, d.Type
	case string(permissions.ResourceTypeGRPCAPI):
		return map[string]string{"service": d.Service, "method": d.Method}, d.Type
	case string(permissions.ResourceTypeGraphQLAPI):
		return map[string]string{"op": d.Op, "field": d.Field}, d.Type
	default:
		return nil, ""
	}
}
