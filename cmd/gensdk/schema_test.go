package main

import "testing"

// docAny is a small helper for building test fixtures shaped like a
// goccy/go-yaml decode of an OpenAPI document (map[string]interface{}
// throughout, matching what Resolve/resolvePrimitive expect).
func docAny(schemas map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"components": map[string]interface{}{"schemas": schemas},
	}
}

func TestResolve_Primitives(t *testing.T) {
	reg := NewRegistry(docAny(nil))
	cases := []struct {
		name string
		node map[string]interface{}
		kind Kind
	}{
		{"string", map[string]interface{}{"type": "string"}, KindString},
		{"integer", map[string]interface{}{"type": "integer"}, KindInteger},
		{"number", map[string]interface{}{"type": "number"}, KindNumber},
		{"boolean", map[string]interface{}{"type": "boolean"}, KindBoolean},
		{"empty object", map[string]interface{}{"type": "object"}, KindObject},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reg.Resolve(c.node)
			if got.Kind != c.kind {
				t.Errorf("Resolve(%v).Kind = %v, want %v", c.node, got.Kind, c.kind)
			}
		})
	}
}

func TestResolve_EnumAndArray(t *testing.T) {
	reg := NewRegistry(docAny(nil))
	str := reg.Resolve(map[string]interface{}{
		"type": "string",
		"enum": []interface{}{"a", "b"},
	})
	if len(str.Enum) != 2 || str.Enum[0] != "a" || str.Enum[1] != "b" {
		t.Fatalf("enum = %v", str.Enum)
	}
	arr := reg.Resolve(map[string]interface{}{
		"type":  "array",
		"items": map[string]interface{}{"type": "string"},
	})
	if arr.Kind != KindArray || arr.Elem.Kind != KindString {
		t.Fatalf("array = %+v", arr)
	}
}

func TestResolve_RefAndSelfReferenceCycle(t *testing.T) {
	// MenuItem.children -> $ref MenuItem is a REAL shape in
	// docs/openapi.yaml; ensureNamed's placeholder-before-recurse guard is
	// what keeps this from looping forever (see schema.go's doc).
	schemas := map[string]interface{}{
		"MenuItem": map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"id": map[string]interface{}{"type": "string"},
				"children": map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"$ref": "#/components/schemas/MenuItem"},
				},
			},
		},
	}
	reg := NewRegistry(docAny(schemas))
	ts := reg.Resolve(map[string]interface{}{"$ref": "#/components/schemas/MenuItem"})
	if ts.Kind != KindRef || ts.Name != "MenuItem" {
		t.Fatalf("top-level resolve = %+v", ts)
	}
	named := reg.NamedType("MenuItem")
	if named == nil || named.Kind != KindObject {
		t.Fatalf("named MenuItem = %+v", named)
	}
	var childrenField *Field
	for i := range named.Fields {
		if named.Fields[i].Name == "children" {
			childrenField = &named.Fields[i]
		}
	}
	if childrenField == nil {
		t.Fatal("MenuItem.children field not found")
	}
	if childrenField.Type.Kind != KindArray || childrenField.Type.Elem.Kind != KindRef ||
		childrenField.Type.Elem.Name != "MenuItem" {
		t.Fatalf("children field type = %+v", childrenField.Type)
	}
	if names := reg.Named(); len(names) != 1 || names[0] != "MenuItem" {
		t.Fatalf("Named() = %v, want exactly [MenuItem]", names)
	}
}

func TestResolve_OneOfUnionAndSingleAllOf(t *testing.T) {
	reg := NewRegistry(docAny(nil))
	union := reg.Resolve(map[string]interface{}{
		"oneOf": []interface{}{
			map[string]interface{}{"type": "string"},
			map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		},
	})
	if union.Kind != KindUnion || len(union.Variants) != 2 {
		t.Fatalf("oneOf = %+v", union)
	}

	schemas := map[string]interface{}{
		"Target": map[string]interface{}{"type": "string"},
	}
	reg2 := NewRegistry(docAny(schemas))
	allOf := reg2.Resolve(map[string]interface{}{
		"allOf": []interface{}{map[string]interface{}{"$ref": "#/components/schemas/Target"}},
	})
	if allOf.Kind != KindRef || allOf.Name != "Target" {
		t.Fatalf("single-entry allOf = %+v, want a KindRef to Target", allOf)
	}
}

func TestResolve_MapVsObject(t *testing.T) {
	reg := NewRegistry(docAny(nil))
	m := reg.Resolve(map[string]interface{}{
		"type":                 "object",
		"additionalProperties": map[string]interface{}{"type": "string"},
	})
	if m.Kind != KindMap || m.Elem.Kind != KindString {
		t.Fatalf("additionalProperties-only object = %+v", m)
	}
	// additionalProperties: true (a bool, not a schema) alongside named
	// fields — e.g. AuthorizationDetail — must NOT collapse to KindMap;
	// it stays KindObject with its named Fields.
	withBoolAP := reg.Resolve(map[string]interface{}{
		"type":                 "object",
		"properties":           map[string]interface{}{"type": map[string]interface{}{"type": "string"}},
		"additionalProperties": true,
	})
	if withBoolAP.Kind != KindObject || len(withBoolAP.Fields) != 1 {
		t.Fatalf("object with bool additionalProperties = %+v", withBoolAP)
	}
}
