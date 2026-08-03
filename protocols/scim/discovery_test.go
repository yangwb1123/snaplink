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

func TestSchemas_AdvertisesCompleteEnterpriseUserExtension(t *testing.T) {
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
		if schema.ID == SchemaEnterpriseUser {
			assertEnterpriseSchemaAttributes(t, schema.Attributes)
			return
		}
	}
	t.Fatal("enterprise User extension is missing from /Schemas")
}

func assertEnterpriseSchemaAttributes(t *testing.T, attrs []schemaAttribute) {
	t.Helper()
	want := map[string]bool{
		"employeeNumber": false, "costCenter": false, "organization": false,
		"division": false, "department": false, "manager": false,
	}
	for _, attr := range attrs {
		if _, ok := want[attr.Name]; ok {
			want[attr.Name] = true
		}
		if attr.Name == "manager" {
			assertSchemaAttributeNames(t, attr.SubAttributes, "value", "$ref", "displayName")
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("enterprise schema omitted %q", name)
		}
	}
}

func assertSchemaAttributeNames(t *testing.T, attrs []schemaAttribute, names ...string) {
	t.Helper()
	for _, name := range names {
		found := false
		for _, attr := range attrs {
			found = found || attr.Name == name
		}
		if !found {
			t.Errorf("schema omitted sub-attribute %q", name)
		}
	}
}
