package apidocs

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

const testSpec = `
openapi: 3.0.3
info:
  title: Test API
  version: "1.2.3"
paths:
  /widgets:
    get:
      operationId: listWidgets
      responses:
        "200":
          description: ok
`

func TestNew_ParsesAndServesUIAndSpec(t *testing.T) {
	ui, spec, err := New([]byte(testSpec))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/admin/docs", nil)
	ui(core.NewContext(rec, req))
	if rec.Code != 200 {
		t.Fatalf("UI status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("UI Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("UI Cache-Control = %q, want no-store", cc)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Test API") {
		t.Error("UI body missing title from spec info.title")
	}
	if !strings.Contains(body, "v1.2.3") {
		t.Error("UI body missing version from spec info.version")
	}
	if !strings.Contains(body, `"listWidgets"`) {
		t.Error("UI body missing inlined spec JSON (operationId)")
	}

	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/api/v1/admin/docs/openapi.json", nil)
	spec(core.NewContext(rec2, req2))
	if rec2.Code != 200 {
		t.Fatalf("spec status = %d, want 200", rec2.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(rec2.Body.Bytes(), &doc); err != nil {
		t.Fatalf("spec body is not valid JSON: %v", err)
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || paths["/widgets"] == nil {
		t.Fatalf("spec JSON missing /widgets path: %#v", doc["paths"])
	}
}

func TestNew_MalformedSpecFailsSafe(t *testing.T) {
	_, _, err := New([]byte("not: [valid: yaml: at all"))
	if err == nil {
		t.Fatal("expected an error for malformed YAML, got nil")
	}
}

// TestNew_ToleratesDuplicateTopLevelKey guards against a real regression:
// docs/openapi.yaml has one known duplicate top-level path key (two
// unrelated sections both happen to document
// /api/v1/admin/tokens/revoke). Without yaml.AllowDuplicateMapKey, New
// would fail to parse the real embedded spec at all.
func TestNew_ToleratesDuplicateTopLevelKey(t *testing.T) {
	const dup = `
openapi: 3.0.3
info: {title: T, version: "1"}
paths:
  /x:
    get: {operationId: firstX, responses: {"200": {description: ok}}}
  /x:
    post: {operationId: secondX, responses: {"200": {description: ok}}}
`
	_, spec, err := New([]byte(dup))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := httptest.NewRecorder()
	spec(core.NewContext(rec, httptest.NewRequest("GET", "/", nil)))
	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("spec body is not valid JSON: %v", err)
	}
	// Last value wins (ordinary lenient YAML/JSON parser behavior).
	x := doc["paths"].(map[string]any)["/x"].(map[string]any)
	if _, hasGet := x["get"]; hasGet {
		t.Error("expected the first /x entry to be shadowed by the second (last-wins)")
	}
	if _, hasPost := x["post"]; !hasPost {
		t.Error("expected the second /x entry (post) to win")
	}
}
