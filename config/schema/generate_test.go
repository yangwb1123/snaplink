package schema

import (
	"testing"
	"time"
)

type innerTestConfig struct {
	Name string `yaml:"name"`
}

type testConfig struct {
	// Required candidate: scalar, no omitempty.
	Issuer string `yaml:"issuer"`
	// Not required: omitempty.
	Optional string `yaml:"optional,omitempty"`
	// Not required: nested struct, even without omitempty.
	Inner innerTestConfig `yaml:"inner"`
	// Not required: pointer, even without omitempty.
	Flag *bool `yaml:"flag"`
	// Not required: slice.
	Tags []string `yaml:"tags"`
	// Not required: map.
	Headers map[string]string `yaml:"headers"`
	Timeout time.Duration     `yaml:"timeout"`
	Skipped string            `yaml:"-"`
	NoTag   int               // falls back to lowercased field name
}

func generateTestDoc() *Document {
	return Generate(testConfig{})
}

func TestGenerate_RootIsObjectWithSchemaAndTitle(t *testing.T) {
	doc := generateTestDoc()
	if doc.Schema != Draft07 {
		t.Errorf("Schema = %q, want %q", doc.Schema, Draft07)
	}
	if doc.Title != "testConfig" {
		t.Errorf("Title = %q, want %q", doc.Title, "testConfig")
	}
	if doc.Type != "object" {
		t.Errorf("Type = %q, want object", doc.Type)
	}
	if doc.AdditionalProperties == nil || *doc.AdditionalProperties {
		t.Errorf("AdditionalProperties = %v, want pointer to false", doc.AdditionalProperties)
	}
}

func TestGenerate_SkipsYAMLDashField(t *testing.T) {
	doc := generateTestDoc()
	if _, ok := doc.Properties["Skipped"]; ok {
		t.Error("yaml:\"-\" field must not appear in Properties")
	}
	if _, ok := doc.Properties["skipped"]; ok {
		t.Error("yaml:\"-\" field must not appear in Properties (lowercase either)")
	}
}

func TestGenerate_FallsBackToLowercasedFieldName(t *testing.T) {
	doc := generateTestDoc()
	child, ok := doc.Properties["notag"]
	if !ok {
		t.Fatal("expected a property for the untagged NoTag field, keyed by lowercased Go name")
	}
	if child.Type != "integer" {
		t.Errorf("NoTag Type = %q, want integer", child.Type)
	}
}

func TestGenerate_RequiredHeuristic(t *testing.T) {
	doc := generateTestDoc()
	required := map[string]bool{}
	for _, r := range doc.Required {
		required[r] = true
	}
	if !required["issuer"] {
		t.Error("issuer (scalar, no omitempty) should be required")
	}
	// timeout (time.Duration, no omitempty) is ALSO a plain-scalar leaf under
	// the documented heuristic — time.Duration only gets special (string)
	// TYPE treatment, not an exemption from the required heuristic.
	if !required["timeout"] {
		t.Error("timeout (duration scalar, no omitempty) should be required under the documented heuristic")
	}
	for _, notRequired := range []string{"optional", "inner", "flag", "tags", "headers"} {
		if required[notRequired] {
			t.Errorf("%s should NOT be required", notRequired)
		}
	}
}

func TestGenerate_NestedStruct(t *testing.T) {
	doc := generateTestDoc()
	inner, ok := doc.Properties["inner"]
	if !ok {
		t.Fatal("expected an 'inner' property")
	}
	if inner.Type != "object" {
		t.Errorf("inner.Type = %q, want object", inner.Type)
	}
	nameDoc, ok := inner.Properties["name"]
	if !ok {
		t.Fatal("expected inner.properties.name")
	}
	if nameDoc.Type != "string" {
		t.Errorf("inner.name.Type = %q, want string", nameDoc.Type)
	}
}

func TestGenerate_PointerBoolBecomesBoolean(t *testing.T) {
	doc := generateTestDoc()
	flag, ok := doc.Properties["flag"]
	if !ok {
		t.Fatal("expected a 'flag' property")
	}
	if flag.Type != "boolean" {
		t.Errorf("flag.Type = %q, want boolean (pointer unwrapped)", flag.Type)
	}
}

func TestGenerate_Slice(t *testing.T) {
	doc := generateTestDoc()
	tags, ok := doc.Properties["tags"]
	if !ok {
		t.Fatal("expected a 'tags' property")
	}
	if tags.Type != "array" {
		t.Errorf("tags.Type = %q, want array", tags.Type)
	}
	if tags.Items == nil || tags.Items.Type != "string" {
		t.Errorf("tags.Items = %+v, want string item schema", tags.Items)
	}
}

func TestGenerate_MapHasNoAdditionalPropertiesRestriction(t *testing.T) {
	doc := generateTestDoc()
	headers, ok := doc.Properties["headers"]
	if !ok {
		t.Fatal("expected a 'headers' property")
	}
	if headers.Type != "object" {
		t.Errorf("headers.Type = %q, want object", headers.Type)
	}
	if headers.AdditionalProperties != nil {
		t.Errorf("headers.AdditionalProperties = %v, want nil (dynamic keys allowed)", headers.AdditionalProperties)
	}
}

func TestGenerate_DurationIsString(t *testing.T) {
	doc := generateTestDoc()
	timeout, ok := doc.Properties["timeout"]
	if !ok {
		t.Fatal("expected a 'timeout' property")
	}
	if timeout.Type != "string" {
		t.Errorf("timeout.Type = %q, want string", timeout.Type)
	}
}

func TestGenerate_CycleGuardDoesNotPanic(t *testing.T) {
	type node struct {
		Next *node `yaml:"next"`
	}
	// A self-referential struct (via pointer) must not cause infinite
	// recursion — this exercises the `seen` guard in generateStruct.
	doc := Generate(node{})
	if doc.Type != "object" {
		t.Fatalf("Generate panicked or produced a non-object root: %+v", doc)
	}
}
