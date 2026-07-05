package main

import "sort"

// Kind classifies a resolved OpenAPI schema node into the small set of
// shapes the TS/Python emitters need to render. This is deliberately NOT a
// full JSON-Schema model (no discriminators, no multi-entry allOf merge,
// no format-specific refinement) — see the package doc for the scope this
// buys.
type Kind int

const (
	KindString Kind = iota
	KindInteger
	KindNumber
	KindBoolean
	KindArray
	KindObject
	KindRef // named component schema; resolved body lives in Registry.named
	KindMap // additionalProperties-only object (no named fields)
	KindUnion
	KindAny // fallback: whatever wasn't handled above (e.g. multi-entry allOf)
)

// Field is one named property of a KindObject TypeSpec.
type Field struct {
	Name     string
	Type     *TypeSpec
	Required bool
	Doc      string // first line of the property's `description`, if any
}

// TypeSpec is a resolved schema, shared by both language emitters. A
// $ref always resolves to Kind==KindRef + Name (never expanded inline) —
// that is what makes self-referential schemas (e.g. MenuItem.children ->
// MenuItem) representable without infinite recursion: the named body is
// resolved exactly once and stored in Registry.named, and every use site
// just references it by name.
type TypeSpec struct {
	Kind     Kind
	Name     string // KindRef: referenced schema name
	Elem     *TypeSpec
	Fields   []Field
	Enum     []string
	Variants []*TypeSpec
	Doc      string // schema-level `description`, first line only
}

// Registry resolves schema nodes against one parsed OpenAPI document,
// memoizing every named (components.schemas) type it encounters so each
// is emitted exactly once regardless of how many operations reference it.
type Registry struct {
	schemas map[string]any
	named   map[string]*TypeSpec
}

// NewRegistry extracts components.schemas from doc (the goccy/go-yaml
// decode of docs/openapi.yaml into `any`) for $ref resolution.
func NewRegistry(doc map[string]any) *Registry {
	r := &Registry{named: map[string]*TypeSpec{}}
	if comps, ok := doc["components"].(map[string]interface{}); ok {
		if schemas, ok := comps["schemas"].(map[string]interface{}); ok {
			r.schemas = schemas
		}
	}
	return r
}

// Named returns every component schema this Registry resolved, sorted by
// name — the emitters' deterministic iteration order.
func (r *Registry) Named() []string {
	names := make([]string, 0, len(r.named))
	for name := range r.named {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// NamedType returns the resolved body for a named schema (nil if unknown).
func (r *Registry) NamedType(name string) *TypeSpec { return r.named[name] }

// Resolve turns one raw schema node (a map[string]interface{}, as decoded
// by goccy/go-yaml) into a TypeSpec.
func (r *Registry) Resolve(node any) *TypeSpec {
	m, ok := node.(map[string]interface{})
	if !ok {
		return &TypeSpec{Kind: KindAny}
	}
	if ts := r.resolveRef(m); ts != nil {
		return ts
	}
	if ts := r.resolveComposition(m); ts != nil {
		return ts
	}
	return r.resolvePrimitive(m)
}

// resolveRef handles "$ref": lazily resolves + memoizes the referenced
// named schema (ensureNamed), then returns a lightweight KindRef pointing
// at it by name. Returns nil when node has no $ref, so callers can fall
// through to the next resolution step.
func (r *Registry) resolveRef(m map[string]interface{}) *TypeSpec {
	ref, ok := m["$ref"].(string)
	if !ok {
		return nil
	}
	name := lastPathSegment(ref)
	r.ensureNamed(name)
	return &TypeSpec{Kind: KindRef, Name: name}
}

// resolveComposition handles the two allOf/oneOf shapes this generator
// supports: a single-entry allOf (equivalent to its one member — the only
// shape docs/openapi.yaml actually uses, e.g. LoginResponse.menus) and
// oneOf/anyOf (a union of the resolved variants — e.g. IntrospectResponse's
// `aud: oneOf[string, array<string>]`, or a whole operation's 200 response
// oneOf-ing several named schemas). A multi-entry allOf (not present in the
// curated operation surface today) is intentionally NOT merged — see the
// package doc's scope note — and falls through to resolvePrimitive, which
// returns KindAny for it.
func (r *Registry) resolveComposition(m map[string]interface{}) *TypeSpec {
	if allOf, ok := m["allOf"].([]interface{}); ok && len(allOf) == 1 {
		return r.Resolve(allOf[0])
	}
	variants, ok := m["oneOf"].([]interface{})
	if !ok {
		variants, ok = m["anyOf"].([]interface{})
	}
	if !ok || len(variants) == 0 {
		return nil
	}
	out := make([]*TypeSpec, 0, len(variants))
	for _, v := range variants {
		out = append(out, r.Resolve(v))
	}
	return &TypeSpec{Kind: KindUnion, Variants: out}
}

// ensureNamed resolves components.schemas[name] exactly once. The
// placeholder assignment BEFORE recursing is what breaks self-reference
// cycles (MenuItem.children -> $ref MenuItem re-enters here mid-resolve;
// the map already has an entry, so resolveRef's caller just gets the
// KindRef stub back instead of looping forever).
func (r *Registry) ensureNamed(name string) {
	if _, done := r.named[name]; done {
		return
	}
	r.named[name] = &TypeSpec{Kind: KindAny}
	node, ok := r.schemas[name]
	if !ok {
		return // dangling $ref; leave the KindAny placeholder
	}
	resolved := r.Resolve(node)
	if m, ok := node.(map[string]interface{}); ok {
		resolved.Doc = firstLine(stringField(m, "description"))
	}
	r.named[name] = resolved
}
