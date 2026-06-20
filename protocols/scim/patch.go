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
// supports: a top-level attribute ("active", "userName", "displayName",
// "externalId", "emails", "members"), the nested form "name.<sub>", and a
// value-path filter on a multi-valued attribute
// ("emails[type eq \"work\"]" and "emails[type eq \"work\"].value"). attr +
// sub are lower-cased because SCIM attribute names are case-insensitive
// (RFC 7643 §2.1). filter is non-nil only when the path carried a [..]
// value selector; it is evaluated against each multi-valued element to
// target the matching one(s).
type patchPath struct {
	attr   string
	sub    string
	filter filterExpr
}

// parsePatchPath splits a PATCH path into attr[.sub] or
// attr[<valueFilter>][.sub]. ok=false signals a shape this slice can't honor
// (empty after the dot, an unparseable value filter, a schema-URN-qualified
// path, or more than one level of nesting) so the caller returns
// scimTypeInvalidPath instead of silently dropping the op.
func parsePatchPath(raw string) (patchPath, bool) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return patchPath{}, false
	}
	// A schema-URN-qualified path ("urn:...:User:active") is beyond this
	// parser; reject it (the value-filter's own quoted string can't contain a
	// colon outside quotes for the attributes we model, so a top-level colon
	// is always a schema URN).
	if strings.Contains(p, ":") {
		return patchPath{}, false
	}
	if strings.ContainsAny(p, "[]") {
		return parseValuePath(p)
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

// parseValuePath parses a value-path PATCH selector
// ("attr[<valueFilter>]" or "attr[<valueFilter>].<sub>", RFC 7644 §3.5.2).
// The value filter reuses the same SCIM filter parser the ?filter= query
// uses, so the supported operator/logical subset is identical. ok=false on
// any malformed shape (unbalanced brackets, empty attr, empty/unparseable
// filter, trailing garbage) so the caller returns scimTypeInvalidPath.
func parseValuePath(p string) (patchPath, bool) {
	open := strings.IndexByte(p, '[')
	close := strings.IndexByte(p, ']')
	// The bracket pair must be well-formed: open before close, and a
	// non-empty attribute name precedes the '['.
	if open <= 0 || close < open+1 {
		return patchPath{}, false
	}
	attr := strings.ToLower(strings.TrimSpace(p[:open]))
	if attr == "" {
		return patchPath{}, false
	}
	inner := strings.TrimSpace(p[open+1 : close])
	if inner == "" {
		return patchPath{}, false
	}
	expr, err := parseFilter(inner)
	if err != nil {
		return patchPath{}, false
	}
	pp := patchPath{attr: attr, filter: expr}
	// An optional ".<sub>" may follow the closing bracket
	// ("emails[type eq \"work\"].value"); anything else after ']' is garbage.
	rest := p[close+1:]
	if rest == "" {
		return pp, true
	}
	if !strings.HasPrefix(rest, ".") {
		return patchPath{}, false
	}
	sub := strings.ToLower(strings.TrimSpace(rest[1:]))
	if sub == "" || strings.ContainsAny(sub, ".[]") {
		return patchPath{}, false
	}
	pp.sub = sub
	return pp, true
}

// isAttr reports whether the parsed (lower-cased) top-level attribute
// equals the given SCIM attribute name, case-insensitively. The path
// attribute consts are mixed-case wire names ("userName"); the parser
// lower-cases the inbound path, so the comparison must fold case.
func (pp patchPath) isAttr(name string) bool {
	return pp.attr == strings.ToLower(name)
}
