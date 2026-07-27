package schema_test

// External test package (schema_test, not schema) so this file can import
// config without creating a real import cycle: config/source.go imports
// config/schema (package schema), but nothing in package schema imports
// config — only this _test.go file does, and Go compiles external test
// packages as a separate unit from the package under test.

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/config/schema"
)

func TestGenerate_RealConfigDoesNotPanicAndHasKnownSections(t *testing.T) {
	doc := schema.Generate(config.Config{})
	if doc.Type != "object" {
		t.Fatalf("root Type = %q, want object", doc.Type)
	}
	for _, section := range []string{"server", "logging", "security", "oauth", "clients", "feature_gates"} {
		if _, ok := doc.Properties[section]; !ok {
			t.Errorf("expected top-level property %q in generated schema", section)
		}
	}
}

func TestGenerate_RealConfigNestedSectionsAreNeverRequired(t *testing.T) {
	// Regression guard for the required-ness heuristic: nested config
	// sections (structs) must never land in Required, even though none of
	// their yaml tags carry omitempty — see generateStruct's doc.
	doc := schema.Generate(config.Config{})
	required := map[string]bool{}
	for _, r := range doc.Required {
		required[r] = true
	}
	for _, section := range []string{"server", "logging", "security", "oauth", "clients", "feature_gates"} {
		if required[section] {
			t.Errorf("%q is a nested section/slice and must not be Required", section)
		}
	}
}

func TestValidate_RealConfigCatchesTypoedKey(t *testing.T) {
	doc := schema.Generate(config.Config{})
	merged := map[string]any{
		"server": map[string]any{
			"issur": "https://sso.example.com", // typo of "issuer"
		},
	}
	violations := schema.Validate(doc, merged)
	found := false
	for _, v := range violations {
		if v.Path == "server.issur" && v.Kind == "unknown_field" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected server.issur to be flagged as unknown_field, got %+v", violations)
	}
}

func TestValidate_RealConfigAcceptsAWellFormedDocument(t *testing.T) {
	doc := schema.Generate(config.Config{})
	merged := map[string]any{
		"server": map[string]any{
			"issuer":      "https://sso.example.com",
			"session_ttl": "24h",
			"token_ttl":   "1h",
		},
		"logging": map[string]any{
			"level": "info",
		},
		"security": map[string]any{
			"rate_limit": map[string]any{
				"enabled":         true,
				"default_per_sec": 10.0,
				"default_burst":   20,
			},
		},
	}
	if v := schema.Validate(doc, merged); len(v) != 0 {
		t.Errorf("expected a well-formed document to pass, got %+v", v)
	}
}
