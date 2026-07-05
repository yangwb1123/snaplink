package main

import "sort"

// resolvePrimitive handles every schema shape without a $ref/allOf/oneOf
// wrapper: arrays, objects (named-field or additionalProperties-only map,
// or a bare `type: object` with neither — e.g. /auth/send-code's empty
// 200 body), and the JSON primitives (string, with optional enum;
// integer; number; boolean). An unrecognized/missing `type` falls back to
// KindAny rather than guessing.
func (r *Registry) resolvePrimitive(m map[string]interface{}) *TypeSpec {
	typ, _ := m["type"].(string)
	switch typ {
	case "array":
		items, _ := m["items"].(map[string]interface{})
		return &TypeSpec{Kind: KindArray, Elem: r.Resolve(items)}
	case "string":
		return &TypeSpec{Kind: KindString, Enum: stringSlice(m["enum"])}
	case "integer":
		return &TypeSpec{Kind: KindInteger}
	case "number":
		return &TypeSpec{Kind: KindNumber}
	case "boolean":
		return &TypeSpec{Kind: KindBoolean}
	case "object", "":
		return r.resolveObjectLike(m)
	default:
		return &TypeSpec{Kind: KindAny}
	}
}

// resolveObjectLike handles the three object shapes docs/openapi.yaml
// uses: named properties (KindObject with Fields — the common case),
// additionalProperties-only free-form maps (KindMap — e.g. `credential`,
// `attributes`; a schema-typed additionalProperties is required, a bare
// `additionalProperties: true` like AuthorizationDetail's is deliberately
// NOT modeled as a map since it carries named fields too — see the
// package doc), and neither (an untyped placeholder object, e.g.
// /device/verify's empty 200 body).
func (r *Registry) resolveObjectLike(m map[string]interface{}) *TypeSpec {
	if props, ok := m["properties"].(map[string]interface{}); ok && len(props) > 0 {
		return r.resolveFields(m, props)
	}
	if ap, ok := m["additionalProperties"].(map[string]interface{}); ok {
		return &TypeSpec{Kind: KindMap, Elem: r.Resolve(ap)}
	}
	return &TypeSpec{Kind: KindObject}
}

// resolveFields builds a KindObject's Fields in alphabetical order.
// docs/openapi.yaml's authored (YAML source) field order isn't
// recoverable here — goccy/go-yaml decodes a mapping node into a plain
// map[string]interface{} for an `any` target, which Go itself does not
// iterate in a stable order — so alphabetical is this generator's
// deliberate, deterministic substitute: regenerating twice yields
// byte-identical output, which authored order alone would not guarantee.
func (r *Registry) resolveFields(m, props map[string]interface{}) *TypeSpec {
	required := stringSet(m["required"])
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]Field, 0, len(names))
	for _, name := range names {
		propNode, _ := props[name].(map[string]interface{})
		fields = append(fields, Field{
			Name:     name,
			Type:     r.Resolve(propNode),
			Required: required[name],
			Doc:      firstLine(stringField(propNode, "description")),
		})
	}
	return &TypeSpec{Kind: KindObject, Fields: fields}
}

// stringSlice converts a decoded YAML `enum:` list (`[]interface{}` of
// strings) to []string; nil/wrong-shaped input yields nil.
func stringSlice(v any) []string {
	list, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// stringSet converts a decoded YAML `required:` list to a lookup set.
func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	for _, s := range stringSlice(v) {
		out[s] = true
	}
	return out
}

// stringField reads a string-valued key from a possibly-nil map without
// panicking — every schema/parameter/operation node in the decoded spec
// is optional, so this is the one guarded accessor the rest of the
// generator uses for `description`/`summary`/etc.
func stringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

// firstLine trims a (possibly multi-paragraph, YAML block-scalar)
// description down to its first line, for compact single-line doc
// comments in the generated code.
func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// lastPathSegment extracts the schema name from a JSON-pointer $ref like
// "#/components/schemas/TokenRequest" -> "TokenRequest".
func lastPathSegment(ref string) string {
	i := len(ref) - 1
	for i >= 0 && ref[i] != '/' {
		i--
	}
	return ref[i+1:]
}
