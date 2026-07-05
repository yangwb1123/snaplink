package schema

import "fmt"

// Violation describes one mismatch between a merged config document and a
// generated Document, found by Validate.
type Violation struct {
	// Path is a dotted path to the offending key, e.g.
	// "security.rate_limit.default_per_sec" or "clients[2].redirect_uris".
	Path string
	// Kind is "unknown_field" (a key with no matching Document.Properties
	// entry, under an object whose AdditionalProperties is false) or
	// "type_mismatch" (the value's runtime shape doesn't match Document.Type).
	Kind string
	// Expected is the schema type ("type_mismatch" only).
	Expected string
	// Got is the Go type of the offending value ("type_mismatch" only).
	Got string
}

// String renders a Violation as "path: unknown field" or
// "path: expected TYPE, got TYPE".
func (v Violation) String() string {
	if v.Kind == "type_mismatch" {
		return fmt.Sprintf("%s: expected %s, got %s", v.Path, v.Expected, v.Got)
	}
	return fmt.Sprintf("%s: unknown field", v.Path)
}

// Validate walks merged — the map[string]any config.Loader builds by
// deep-merging every Source, BEFORE it decodes the result into
// *config.Config — against doc and returns every violation found, at any
// nesting depth. This improves on a single-level, regex-based unknown-key
// scan (config.extractUnknownFields) in two ways: it sees keys nested
// arbitrarily deep, and it reports each one's full dotted path.
//
// Two things Validate deliberately does NOT do:
//
//  1. Enforce Document.Required. Go's zero-value defaulting means every
//     field in config.Config is decodable when absent from YAML (see
//     config.Config.applyDefaults) — a strict required-field check would
//     reject configs that rely on a documented default. Required exists on
//     Document purely as an IDE/documentation aid (see generateStruct's doc
//     for its own heuristic limits).
//
//  2. Hard-fail the caller. The reflection-based Document cannot capture
//     every decode-time flexibility goccy/go-yaml offers (the clearest
//     example: time.Duration accepts EITHER a duration string or a bare
//     integer nanosecond count, but Document types it "string"). Promoting
//     a Violation straight to a load failure risks rejecting a config that
//     would actually decode fine. The authoritative type check remains the
//     yaml.Unmarshal into *config.Config that runs immediately after in
//     config.decodeStrictWithFallback — Validate's violations are reported
//     as warnings alongside it (see config/source.go), and are promoted to
//     a hard gate only in the explicit, operator-invoked
//     `sso-ctl config validate-schema` CI check.
func Validate(doc *Document, merged map[string]any) []Violation {
	var out []Violation
	walk("", doc, any(merged), &out)
	return out
}

// walk dispatches on doc.Type, recursing into objects/arrays and comparing
// scalar leaves. A nil value (YAML null, or an absent key one level up)
// is always accepted — omission/null is exactly what "not required"
// means throughout this config. Split into one helper per doc.Type
// category (object/array/scalar) to keep cyclomatic complexity down —
// see walkObjectCase/walkArrayCase/walkScalarCase.
func walk(path string, doc *Document, value any, out *[]Violation) {
	if value == nil || doc == nil {
		return
	}
	switch doc.Type {
	case "object":
		walkObjectCase(path, doc, value, out)
	case "array":
		walkArrayCase(path, doc, value, out)
	default:
		walkScalarCase(path, doc, value, out)
	}
}

func walkObjectCase(path string, doc *Document, value any, out *[]Violation) {
	m, ok := value.(map[string]any)
	if !ok {
		*out = append(*out, mismatch(path, "object", value))
		return
	}
	walkObject(path, doc, m, out)
}

func walkArrayCase(path string, doc *Document, value any, out *[]Violation) {
	s, ok := value.([]any)
	if !ok {
		*out = append(*out, mismatch(path, "array", value))
		return
	}
	for i, item := range s {
		walk(fmt.Sprintf("%s[%d]", path, i), doc.Items, item, out)
	}
}

// walkScalarCase handles every non-object/array doc.Type: "string",
// "boolean", "integer"/"number", and "" (any/interface{}/dynamic-map value
// — accepts anything, the JSON-Schema-style default).
func walkScalarCase(path string, doc *Document, value any, out *[]Violation) {
	switch doc.Type {
	case "string":
		if _, ok := value.(string); !ok && !isDurationCompatible(doc, value) {
			*out = append(*out, mismatch(path, "string", value))
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			*out = append(*out, mismatch(path, "boolean", value))
		}
	case "integer", "number":
		if !isNumeric(value) {
			*out = append(*out, mismatch(path, doc.Type, value))
		}
	}
}

// isDurationCompatible tolerates a bare integer where the schema says
// "string" — but ONLY for a Document tagged FormatDuration (time.Duration,
// see generateType). An ordinary string field (e.g. server.issuer) with an
// integer value is still a genuine type mismatch.
func isDurationCompatible(doc *Document, value any) bool {
	return doc.Format == FormatDuration && isNumeric(value)
}

func walkObject(path string, doc *Document, m map[string]any, out *[]Violation) {
	for k, v := range m {
		childPath := joinPath(path, k)
		child, known := doc.Properties[k]
		if !known {
			if doc.AdditionalProperties != nil && !*doc.AdditionalProperties {
				*out = append(*out, Violation{Path: childPath, Kind: "unknown_field"})
			}
			continue
		}
		walk(childPath, child, v, out)
	}
}

func mismatch(path, expected string, got any) Violation {
	return Violation{Path: path, Kind: "type_mismatch", Expected: expected, Got: goType(got)}
}

func goType(v any) string {
	if v == nil {
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

func isNumeric(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return true
	default:
		return false
	}
}

func joinPath(base, key string) string {
	if base == "" {
		return key
	}
	return base + "." + key
}
