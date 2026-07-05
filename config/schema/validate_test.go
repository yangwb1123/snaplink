package schema

import "testing"

func TestValidate_NoViolationsOnMatchingDocument(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"issuer":  "https://sso.example.com",
		"inner":   map[string]any{"name": "x"},
		"flag":    true,
		"tags":    []any{"a", "b"},
		"headers": map[string]any{"X-Custom": "value"},
		"timeout": "30s",
	}
	if v := Validate(doc, merged); len(v) != 0 {
		t.Errorf("expected no violations, got %+v", v)
	}
}

func TestValidate_UnknownTopLevelField(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"issuer":   "x",
		"bogus_ky": "typo",
	}
	violations := Validate(doc, merged)
	found := false
	for _, v := range violations {
		if v.Path == "bogus_ky" && v.Kind == "unknown_field" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an unknown_field violation for bogus_ky, got %+v", violations)
	}
}

func TestValidate_UnknownNestedField(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"inner": map[string]any{"name": "x", "typo_field": 1},
	}
	violations := Validate(doc, merged)
	found := false
	for _, v := range violations {
		if v.Path == "inner.typo_field" && v.Kind == "unknown_field" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected inner.typo_field unknown_field violation, got %+v", violations)
	}
}

func TestValidate_TypeMismatch(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"issuer": 123, // should be a string
	}
	violations := Validate(doc, merged)
	if len(violations) != 1 {
		t.Fatalf("expected exactly 1 violation, got %+v", violations)
	}
	v := violations[0]
	if v.Path != "issuer" || v.Kind != "type_mismatch" || v.Expected != "string" || v.Got != "int" {
		t.Errorf("unexpected violation: %+v", v)
	}
}

func TestValidate_DurationAcceptsIntegerNanoseconds(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"timeout": 5000000000, // bare int, not a duration string
	}
	if v := Validate(doc, merged); len(v) != 0 {
		t.Errorf("expected timeout to accept a bare integer, got %+v", v)
	}
}

func TestValidate_MapAcceptsArbitraryKeys(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"headers": map[string]any{"Anything-Goes": "yes", "Another-One": "sure"},
	}
	if v := Validate(doc, merged); len(v) != 0 {
		t.Errorf("expected map keys to be unrestricted, got %+v", v)
	}
}

func TestValidate_NullValueIsAlwaysAccepted(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"issuer": nil,
		"inner":  nil,
	}
	if v := Validate(doc, merged); len(v) != 0 {
		t.Errorf("expected nil values to be accepted (absence is always valid), got %+v", v)
	}
}

func TestValidate_ArrayElementTypeMismatch(t *testing.T) {
	doc := generateTestDoc()
	merged := map[string]any{
		"tags": []any{"ok", 5},
	}
	violations := Validate(doc, merged)
	found := false
	for _, v := range violations {
		if v.Path == "tags[1]" && v.Kind == "type_mismatch" && v.Expected == "string" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a type_mismatch at tags[1], got %+v", violations)
	}
}

func TestValidate_DoesNotEnforceRequired(t *testing.T) {
	doc := generateTestDoc()
	// Deliberately omit "issuer" (a Required entry) entirely — Validate must
	// NOT flag this, since Go's zero-value defaulting makes every field
	// decodable when absent (see Validate's doc).
	merged := map[string]any{
		"optional": "set",
	}
	if v := Validate(doc, merged); len(v) != 0 {
		t.Errorf("Validate must not enforce Required, got %+v", v)
	}
}

func TestViolation_String(t *testing.T) {
	tm := Violation{Path: "a.b", Kind: "type_mismatch", Expected: "string", Got: "int"}
	if got := tm.String(); got != "a.b: expected string, got int" {
		t.Errorf("String() = %q", got)
	}
	uf := Violation{Path: "a.c", Kind: "unknown_field"}
	if got := uf.String(); got != "a.c: unknown field" {
		t.Errorf("String() = %q", got)
	}
}
