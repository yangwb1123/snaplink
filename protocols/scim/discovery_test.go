package scim

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestSchemas_ExternalIDCaseExactMatchesActualFilterBehavior is the
// regression test for a real spec-compliance bug: GET /Schemas advertised
// externalId as caseExact:true, but filter.go's compareOne (and sort.go's
// keyLess) case-fold externalId along with every other string attribute —
// a provisioning connector trusting the schema's introspection would expect
// case-sensitive filter/sort matching it would never actually get. Proves
// the schema now honestly advertises caseExact:false, matching the tested,
// established filter/sort behavior (filter_test.go, sort_extra_test.go).
func TestSchemas_ExternalIDCaseExactMatchesActualFilterBehavior(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathSchemas, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp struct {
		Resources []SchemaResource `json:"Resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, schema := range resp.Resources {
		for _, attr := range schema.Attributes {
			if attr.Name != "externalId" {
				continue
			}
			if attr.CaseExact {
				t.Errorf("schema %q externalId.caseExact = true, want false (filter/sort actually case-fold it)", schema.ID)
			}
			return
		}
	}
	t.Fatal("no schema declared an externalId attribute")
}
