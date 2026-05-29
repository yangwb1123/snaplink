package scim

import (
	"encoding/json"
	"strings"
)

// PatchRequest is the SCIM PATCH body (RFC 7644 §3.5.2): a schemas array
// naming PatchOp plus an ordered list of operations applied in sequence.
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one entry in PatchRequest.Operations (RFC 7644
// §3.5.2). Op is one of add|replace|remove (case-insensitive). Path is an
// optional attribute path; when empty on add/replace, Value is a
// {attr: val} object applied to the resource root. Value is left as raw
// JSON so the same op shape carries a scalar (active), a string
// (userName), an object (name), or an array (members) and is decoded
// against the target attribute's type at apply time.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value,omitempty"`
}

// normalizedOp lower-cases Op so the case-insensitive "op" of RFC 7644
// §3.5.2 ("Add"/"ADD"/"add" are equal) compares against the verb consts.
func (op PatchOperation) normalizedOp() string {
	return strings.ToLower(strings.TrimSpace(op.Op))
}

// patchPath is a parsed PATCH "path" (RFC 7644 §3.5.2). This slice
// supports the common connector paths only: a top-level attribute
// ("active", "userName", "displayName", "externalId", "emails",
// "members") and the one nested form "name.<sub>". A value filter
// ("members[value eq \"x\"]") is NOT parsed here: Azure AD / Okta
// deprovision and the typical group-member delta use unfiltered paths, so
// a filtered path is reported as an unsupported path rather than
// half-honored. attr + sub are lower-cased because SCIM attribute names
// are case-insensitive (RFC 7643 §2.1).
type patchPath struct {
	attr string
	sub  string
}

// parsePatchPath splits a PATCH path into attr[.sub]. ok=false signals a
// shape this slice can't honor (empty after the dot, a value filter, a
// schema-URN-qualified path, or more than one level of nesting) so the
// caller returns scimTypeInvalidPath instead of silently dropping the op.
func parsePatchPath(raw string) (patchPath, bool) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return patchPath{}, false
	}
	// A value filter ("attr[...]") or a schema-URN-qualified path
	// ("urn:...:User:active") is beyond this minimal parser.
	if strings.ContainsAny(p, "[]") || strings.Contains(p, ":") {
		return patchPath{}, false
	}
	parts := strings.Split(p, ".")
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return patchPath{}, false
		}
		return patchPath{attr: strings.ToLower(parts[0])}, true
	case 2:
		if parts[0] == "" || parts[1] == "" {
			return patchPath{}, false
		}
		return patchPath{attr: strings.ToLower(parts[0]), sub: strings.ToLower(parts[1])}, true
	default:
		return patchPath{}, false
	}
}

// isAttr reports whether the parsed (lower-cased) top-level attribute
// equals the given SCIM attribute name, case-insensitively. The path
// attribute consts are mixed-case wire names ("userName"); the parser
// lower-cases the inbound path, so the comparison must fold case.
func (pp patchPath) isAttr(name string) bool {
	return pp.attr == strings.ToLower(name)
}
