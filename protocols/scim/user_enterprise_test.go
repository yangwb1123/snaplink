package scim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

const enterpriseSchemaURN = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// TestCreateUser_EnterpriseExtensionRoundTrips verifies employeeNumber,
// costCenter, organization, division, department, and manager survive
// create -> get, and that the enterprise schema URN is added to Schemas
// only because an enterprise attribute is actually present.
func TestCreateUser_EnterpriseExtensionRoundTrips(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)

	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "alice@example.com",
		"` + enterpriseSchemaURN + `": {
			"employeeNumber": "701",
			"costCenter": "CC-42",
			"organization": "Engineering Inc",
			"division": "Platform",
			"department": "Identity",
			"manager": {"value": "mgr-1", "displayName": "Bob Manager"}
		}
	}`
	rec := do(t, h, http.MethodPost, pathUsers, createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	created := decodeResource(t, rec)
	assertEnterpriseSchemaPresent(t, created)

	ext := created.EnterpriseExtension
	if ext == nil {
		t.Fatal("EnterpriseExtension nil after create")
	}
	if ext.EmployeeNumber != "701" || ext.CostCenter != "CC-42" || ext.Organization != "Engineering Inc" ||
		ext.Division != "Platform" || ext.Department != "Identity" {
		t.Errorf("enterprise fields = %+v", ext)
	}
	if ext.Manager == nil || ext.Manager.Value != "mgr-1" || ext.Manager.DisplayName != "Bob Manager" {
		t.Errorf("manager = %+v", ext.Manager)
	}

	// GET round-trips the same data.
	rec = do(t, h, http.MethodGet, pathUsers+"/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d; body=%s", rec.Code, rec.Body.String())
	}
	got := decodeResource(t, rec)
	if got.EnterpriseExtension == nil || got.EnterpriseExtension.EmployeeNumber != "701" {
		t.Errorf("get did not round-trip enterprise extension: %+v", got.EnterpriseExtension)
	}
}

// TestCreateUser_NoEnterpriseAttrsOmitsExtension confirms a user with no
// enterprise attribute set gets neither the extension block nor its schema
// URN in the response -- the common non-enterprise-connector case must stay
// byte-identical to before this feature existed.
func TestCreateUser_NoEnterpriseAttrsOmitsExtension(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"plain@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", rec.Code, rec.Body.String())
	}
	created := decodeResource(t, rec)
	if created.EnterpriseExtension != nil {
		t.Errorf("EnterpriseExtension = %+v, want nil", created.EnterpriseExtension)
	}
	for _, s := range created.Schemas {
		if s == enterpriseSchemaURN {
			t.Errorf("schemas = %v, want no enterprise URN", created.Schemas)
		}
	}
}

// TestPatchUser_SetsEnterpriseAttrsViaBarePath exercises PATCH replace with
// an explicit "path" (the RFC 7644 §3.5.2 attribute-path form) for both a
// simple string attribute and the manager complex attribute, confirming
// the wiring added to applyUserPathOp actually takes effect (previously
// every enterprise path fell through to "unsupported PATCH path").
func TestPatchUser_SetsEnterpriseAttrsViaBarePath(t *testing.T) {
	t.Parallel()
	h, users, _ := newTestHandler(t)
	mgrID := seedUser(t, h, `{"userName":"manager@example.com"}`)
	id := seedUser(t, h, `{"userName":"report@example.com"}`)

	body := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [
			{"op": "replace", "path": "employeeNumber", "value": "900"},
			{"op": "replace", "path": "manager", "value": {"value": "` + mgrID + `"}}
		]
	}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got := decodeResource(t, rec)
	if got.EnterpriseExtension == nil || got.EnterpriseExtension.EmployeeNumber != "900" {
		t.Fatalf("employeeNumber not set via PATCH: %+v", got.EnterpriseExtension)
	}
	if got.EnterpriseExtension.Manager == nil || got.EnterpriseExtension.Manager.Value != mgrID {
		t.Fatalf("manager not set via PATCH: %+v", got.EnterpriseExtension.Manager)
	}

	// Persisted, not just echoed.
	u, err := users.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if u.Attributes[attrEmployeeNumber] != "900" {
		t.Errorf("stored employeeNumber = %q, want 900", u.Attributes[attrEmployeeNumber])
	}
}

// TestPatchUser_RemoveManagerClearsExtension confirms a PATCH remove on
// "manager" clears the reference and, when it was the only enterprise
// attribute set, drops the whole extension block back to nil rather than
// rendering an empty one.
func TestPatchUser_RemoveManagerClearsExtension(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	mgrID := seedUser(t, h, `{"userName":"manager2@example.com"}`)
	id := seedUser(t, h, `{"userName":"report2@example.com", "`+enterpriseSchemaURN+`": {"manager": {"value": "`+mgrID+`"}}}`)

	body := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations": [{"op": "remove", "path": "manager"}]
	}`
	rec := do(t, h, http.MethodPatch, pathUsers+"/"+id, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	got := decodeResource(t, rec)
	if got.EnterpriseExtension != nil {
		t.Errorf("EnterpriseExtension = %+v, want nil after removing its only field", got.EnterpriseExtension)
	}
}

// TestReplaceUser_ManagerCycleRejected covers the direct (self) and
// indirect (A -> B -> A) manager-cycle cases via PUT, both of which must be
// rejected with 409 mutability and must NOT mutate the stored user.
func TestReplaceUser_ManagerCycleRejected(t *testing.T) {
	t.Parallel()
	h, users, _ := newTestHandler(t)

	t.Run("self", func(t *testing.T) {
		id := seedUser(t, h, `{"userName":"self-mgr@example.com"}`)
		body := `{"userName":"self-mgr@example.com", "` + enterpriseSchemaURN + `": {"manager": {"value": "` + id + `"}}}`
		rec := do(t, h, http.MethodPut, pathUsers+"/"+id, body)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
		}
		errResp := decodeError(t, rec)
		if errResp.ScimType != scimTypeMutability {
			t.Errorf("scimType = %q, want mutability", errResp.ScimType)
		}
	})

	t.Run("indirect", func(t *testing.T) {
		a := seedUser(t, h, `{"userName":"a@example.com"}`)
		b := seedUser(t, h, `{"userName":"b@example.com", "`+enterpriseSchemaURN+`": {"manager": {"value": "`+a+`"}}}`)

		// Attempt A.manager = B, which would close the cycle A -> B -> A.
		body := `{"userName":"a@example.com", "` + enterpriseSchemaURN + `": {"manager": {"value": "` + b + `"}}}`
		rec := do(t, h, http.MethodPut, pathUsers+"/"+a, body)
		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
		}

		// A must be unchanged (no manager set) -- the rejected PUT must not
		// have partially applied.
		u, err := users.GetByID(context.Background(), a)
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if u.Attributes[attrManager] != "" {
			t.Errorf("A's manager = %q, want empty (rejected update must not apply)", u.Attributes[attrManager])
		}
	})
}

// TestReplaceUser_ManagerNoCycleAccepted is the control case: a valid,
// acyclic manager chain (A -> B, no back-edge) must be accepted.
func TestReplaceUser_ManagerNoCycleAccepted(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	a := seedUser(t, h, `{"userName":"chain-a@example.com"}`)
	b := seedUser(t, h, `{"userName":"chain-b@example.com"}`)

	body := `{"userName":"chain-a@example.com", "` + enterpriseSchemaURN + `": {"manager": {"value": "` + b + `"}}}`
	rec := do(t, h, http.MethodPut, pathUsers+"/"+a, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func assertEnterpriseSchemaPresent(t *testing.T, r Resource) {
	t.Helper()
	for _, s := range r.Schemas {
		if s == enterpriseSchemaURN {
			return
		}
	}
	t.Errorf("schemas = %v, want enterprise URN present", r.Schemas)
}

// --- DetectManagerCycle unit tests (no HTTP layer) ---

func TestDetectManagerCycle_NoCycle(t *testing.T) {
	t.Parallel()
	chain := map[string]string{"b": "c", "c": ""} // a -> b -> c -> (none)
	get := func(_ context.Context, id string) (string, error) { return chain[id], nil }
	if err := DetectManagerCycle(context.Background(), "a", "b", get); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

func TestDetectManagerCycle_SelfReference(t *testing.T) {
	t.Parallel()
	get := func(_ context.Context, id string) (string, error) { return "", nil }
	if err := DetectManagerCycle(context.Background(), "a", "a", get); !errors.Is(err, ErrManagerCycle) {
		t.Errorf("err = %v, want ErrManagerCycle", err)
	}
}

func TestDetectManagerCycle_IndirectCycle(t *testing.T) {
	t.Parallel()
	chain := map[string]string{"b": "c", "c": "a"} // a -> b -> c -> a
	get := func(_ context.Context, id string) (string, error) { return chain[id], nil }
	if err := DetectManagerCycle(context.Background(), "a", "b", get); !errors.Is(err, ErrManagerCycle) {
		t.Errorf("err = %v, want ErrManagerCycle", err)
	}
}

func TestDetectManagerCycle_EmptyInputsAreNoop(t *testing.T) {
	t.Parallel()
	get := func(_ context.Context, id string) (string, error) {
		t.Fatal("getManager must not be called when userID/managerID is empty")
		return "", nil
	}
	if err := DetectManagerCycle(context.Background(), "", "b", get); err != nil {
		t.Errorf("empty userID: err = %v, want nil", err)
	}
	if err := DetectManagerCycle(context.Background(), "a", "", get); err != nil {
		t.Errorf("empty managerID: err = %v, want nil", err)
	}
}

func TestDetectManagerCycle_PropagatesGetManagerError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("boom")
	get := func(_ context.Context, id string) (string, error) { return "", wantErr }
	if err := DetectManagerCycle(context.Background(), "a", "b", get); !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want wantErr", err)
	}
}

// TestDetectManagerCycle_LongChainWithinDepthNoFalsePositive guards against
// an overly aggressive depth cutoff misfiring as a cycle on a long-but-real
// (non-cyclic) chain shorter than maxManagerCycleDepth.
func TestDetectManagerCycle_LongChainWithinDepthNoFalsePositive(t *testing.T) {
	t.Parallel()
	// a -> m1 -> m2 -> ... -> m(maxManagerCycleDepth-1) -> (none)
	chain := map[string]string{}
	for i := 1; i < maxManagerCycleDepth; i++ {
		chain[managerChainID(i)] = managerChainID(i + 1)
	}
	chain[managerChainID(maxManagerCycleDepth)] = ""
	get := func(_ context.Context, id string) (string, error) { return chain[id], nil }
	if err := DetectManagerCycle(context.Background(), "a", managerChainID(1), get); err != nil {
		t.Errorf("err = %v, want nil (chain shorter than depth cap)", err)
	}
}

func managerChainID(i int) string {
	return fmt.Sprintf("m%d", i)
}
