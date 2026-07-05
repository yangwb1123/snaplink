// Package schema generates a lightweight JSON-Schema-like document
// describing a Go struct's shape via reflection over its `yaml` struct
// tags, and validates an already-merged config document (a
// map[string]any — the shape config.Loader builds by deep-merging every
// Source, BEFORE it is decoded into the strongly-typed *config.Config)
// against that document.
//
// This intentionally implements only the handful of JSON Schema (draft-07)
// keywords needed for two concrete uses: (a) `sso-ctl config schema` emits
// a document an editor (e.g. the redhat.vscode-yaml extension) can use for
// autocompletion and typo-detection against config.Config's actual shape,
// and (b) Validate gives operators a path + expected-type violation instead
// of a raw decode error. It is not a general JSON Schema implementation —
// no $ref, oneOf/anyOf, format, or numeric bounds.
//
// Package schema deliberately has NO dependency on package config — it
// operates purely by reflection over whatever type/value is handed to
// Generate. That keeps config -> config/schema a plain one-way import with
// no cycle risk (config/source.go uses this package to add a schema check
// alongside its existing YAML-decode validation).
package schema

import (
	"reflect"
	"sort"
	"strings"
	"time"
)

// Draft07 is the $schema value Generate stamps onto the root Document.
const Draft07 = "http://json-schema.org/draft-07/schema#"

// Document is a minimal JSON Schema node: an object (with Properties +
// Required + AdditionalProperties), an array (with Items), or a scalar
// leaf (Type only). Fields mirror the JSON Schema keywords of the same
// name so Document marshals directly to a valid (if minimal) JSON Schema
// document via encoding/json.
type Document struct {
	Schema               string               `json:"$schema,omitempty"`
	Title                string               `json:"title,omitempty"`
	Type                 string               `json:"type,omitempty"`
	Format               string               `json:"format,omitempty"`
	Properties           map[string]*Document `json:"properties,omitempty"`
	Items                *Document            `json:"items,omitempty"`
	Required             []string             `json:"required,omitempty"`
	AdditionalProperties *bool                `json:"additionalProperties,omitempty"`
}

// FormatDuration marks a "string"-typed Document node as ALSO accepting a
// bare integer (nanoseconds) — the one field kind (time.Duration) whose
// decode-time flexibility is wider than its natural schema type. Not a
// standard JSON Schema format value the way "date-time" is, but harmless
// to a consumer that doesn't recognize it (format is advisory in the
// base spec) and lets Validate distinguish "this string field is really a
// duration" from an ordinary string field, where a bare integer IS a
// genuine type mismatch.
const FormatDuration = "duration"

var durationType = reflect.TypeOf(time.Duration(0))

// Generate builds a Document describing v's type. v is typically a zero
// value of the struct to describe (e.g. Generate(config.Config{})) —
// Generate only inspects v's static type via reflection, never its
// contents, so a zero value works exactly as well as a populated one.
func Generate(v any) *Document {
	t := reflect.TypeOf(v)
	doc := generateType(t, map[reflect.Type]bool{})
	doc.Schema = Draft07
	doc.Title = t.Name()
	return doc
}

// generateType builds the Document for one Go type, recursing into
// structs/slices/maps. seen guards against unbounded recursion on a
// self-referential struct (none exist in config.Config today, but the
// generator is generic over any struct, so the guard is cheap insurance).
func generateType(t reflect.Type, seen map[reflect.Type]bool) *Document {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch {
	case t == durationType:
		// time.Duration decodes from EITHER a duration string ("30s") or a
		// bare integer (nanoseconds) — goccy/go-yaml accepts both. "string"
		// is the documented/conventional form throughout config.yaml, so
		// schema readers (IDEs) get the more useful hint; Format marks it so
		// Validate can still treat a bare integer as compatible (see
		// isDurationCompatible) without weakening ordinary string fields.
		return &Document{Type: "string", Format: FormatDuration}
	case t.Kind() == reflect.Struct:
		return generateStruct(t, seen)
	case t.Kind() == reflect.Slice, t.Kind() == reflect.Array:
		return &Document{Type: "array", Items: generateType(t.Elem(), seen)}
	case t.Kind() == reflect.Map:
		// Dynamic keys (e.g. AuditWebhookConfig.Headers map[string]string) —
		// deliberately no Properties/AdditionalProperties restriction, so
		// Validate never flags an arbitrary map key as "unknown".
		return &Document{Type: "object"}
	case t.Kind() == reflect.String:
		return &Document{Type: "string"}
	case t.Kind() == reflect.Bool:
		return &Document{Type: "boolean"}
	case isIntKind(t.Kind()):
		return &Document{Type: "integer"}
	case t.Kind() == reflect.Float32, t.Kind() == reflect.Float64:
		return &Document{Type: "number"}
	default:
		// interface{}/any and anything else unanticipated: no type
		// restriction, matching JSON Schema's "accept anything" node.
		return &Document{}
	}
}

// generateStruct builds the "object" Document for a struct type, walking
// its exported fields via their `yaml` tag.
//
// Required-ness heuristic: a field is listed in Required only when its tag
// lacks ",omitempty" AND its own (non-pointer, non-struct, non-slice,
// non-map) kind is a plain scalar. This deliberately EXCLUDES:
//   - nested struct sections (e.g. `Server ServerConfig`) — always
//     present with a meaningful zero value after config.Config.applyDefaults,
//     never "must be provided by the operator".
//   - pointer fields (e.g. FeatureGatesConfig's `*bool`s) — nil is a
//     deliberate, meaningful "operator didn't mention this" state in this
//     codebase, not an error.
//   - slices/maps — omitting a list/map is always valid (empty).
//
// Even with these exclusions this is only a heuristic (the same one used
// by most reflection-based Go->JSON-Schema generators): Go's zero-value
// defaulting means a plain scalar field can ALSO always be omitted from
// YAML and decode fine, regardless of ",omitempty" (that tag only affects
// re-MARSHALING, not decoding). Treat Required as a documentation aid for
// IDE tooling, not a strict "the config fails to load without this"
// contract — see Validate's doc for why the validator does not enforce it.
func generateStruct(t reflect.Type, seen map[reflect.Type]bool) *Document {
	if seen[t] {
		return &Document{}
	}
	seen[t] = true
	defer delete(seen, t)

	props := make(map[string]*Document)
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue // unexported
		}
		name, omitEmpty, inline, skip := parseYAMLTag(f)
		if skip {
			continue
		}
		if f.Anonymous && inline {
			// yaml:",inline" (e.g. OAuthRefreshTokenConfig embedding
			// OAuthStoreConfig): goccy/go-yaml decodes the embedded
			// struct's keys as direct siblings of the parent's own keys,
			// NOT nested under a field name — so the embedded struct's
			// Properties/Required are merged straight into this level.
			// Getting this wrong makes Validate flag every one of the
			// embedded struct's real, valid keys as "unknown_field".
			embedded := generateType(f.Type, seen)
			for k, v := range embedded.Properties {
				props[k] = v
			}
			required = append(required, embedded.Required...)
			continue
		}
		props[name] = generateType(f.Type, seen)
		if !omitEmpty && isRequiredCandidate(f.Type) {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	notAdditional := false
	return &Document{
		Type:                 "object",
		Properties:           props,
		Required:             required,
		AdditionalProperties: &notAdditional,
	}
}

// isRequiredCandidate reports whether t's own kind (BEFORE dereferencing —
// a pointer is never a required candidate, see generateStruct's doc) is a
// plain scalar leaf.
func isRequiredCandidate(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Ptr, reflect.Struct, reflect.Slice, reflect.Array, reflect.Map, reflect.Interface:
		return false
	default:
		return true
	}
}

func isIntKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

// parseYAMLTag extracts the field name (falling back to the lowercased Go
// field name when no tag is present), whether ",omitempty" is set, and
// whether ",inline" is set (only meaningful on an anonymous/embedded
// field — see generateStruct's inline handling). skip reports the field
// opted out entirely via `yaml:"-"`.
func parseYAMLTag(f reflect.StructField) (name string, omitEmpty, inline, skip bool) {
	tag := f.Tag.Get("yaml")
	if tag == "-" {
		return "", false, false, true
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	for _, p := range parts[1:] {
		switch p {
		case "omitempty":
			omitEmpty = true
		case "inline":
			inline = true
		}
	}
	return name, omitEmpty, inline, false
}
