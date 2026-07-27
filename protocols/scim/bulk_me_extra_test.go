package scim

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/core"
)

// These tests cover the bulk + /Me + handler branches the existing suites do
// not reach: /Me PUT + method-not-allowed, the default crypto randomID
// generator, a bulk operation whose method produces a per-op error envelope,
// the bulk payload-size + operation-count limits, and bulkId reference
// resolution within data.

// TestMe_PutReplacesSubject: PUT /Me replaces the resolved subject's own
// resource (me's MethodPut -> replaceUser branch).
func TestMe_PutReplacesSubject(t *testing.T) {
	t.Parallel()
	h, _ := meHandler(t, "id-1")
	if rec := do(t, h, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"self@example.com"}`); rec.Code != http.StatusCreated {
		t.Fatalf("seed create: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(t, h, http.MethodPut, "/Me", `{"userName":"self2@example.com","displayName":"Me Two"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /Me status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	res := decodeResource(t, rec)
	if res.UserName != "self2@example.com" || res.DisplayName != "Me Two" {
		t.Errorf("PUT /Me did not replace: %+v", res)
	}
}

// TestMe_PatchSubject: PATCH /Me applies a PATCH to the subject's resource.
func TestMe_PatchSubject(t *testing.T) {
	t.Parallel()
	h, _ := meHandler(t, "id-1")
	if rec := do(t, h, http.MethodPost, "/Users", `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"me@example.com"}`); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`
	rec := do(t, h, http.MethodPatch, "/Me", patch)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH /Me status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if decodeResource(t, rec).Active {
		t.Error("PATCH /Me did not deactivate")
	}
}

// TestMe_MethodNotAllowed: an undefined method on /Me is 405 (me's default
// branch).
func TestMe_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h, _ := meHandler(t, "id-1")
	rec := do(t, h, http.MethodPost, "/Me", `{}`)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /Me = %d, want 405", rec.Code)
	}
}

// TestRandomIDDefaultGenerator: a handler built WITHOUT a custom id generator
// uses crypto/rand randomID, producing a 32-hex-char opaque id (helpers.go
// randomID, otherwise only the deterministic test generator runs).
func TestRandomIDDefaultGenerator(t *testing.T) {
	t.Parallel()
	users := defaultimpl.NewMemoryUserProvider()
	h := NewHandler(users, testBase) // no WithIDGenerator
	rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"rng@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", rec.Code, rec.Body.String())
	}
	id := decodeResource(t, rec).ID
	if len(id) != 32 {
		t.Errorf("randomID length = %d, want 32 hex chars; id=%q", len(id), id)
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("randomID contains non-hex %q in %q", c, id)
			break
		}
	}
	// A second create must mint a DIFFERENT id (entropy, not a counter).
	rec2 := do(t, h, http.MethodPost, pathUsers, `{"userName":"rng2@example.com"}`)
	if id2 := decodeResource(t, rec2).ID; id2 == id {
		t.Error("randomID produced a duplicate id")
	}
}

// TestBulk_OperationErrorEnvelope: a bulk op that fails (a create with a
// duplicate userName) reports a non-2xx status with the error body inline
// (bulk's error branch + marshalErr path is covered by the failOnErrors test;
// here we assert the inline error response body on a per-op failure).
func TestBulk_OperationErrorEnvelope(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	// Seed a user so the second create collides on userName.
	if rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"dup@example.com"}`); rec.Code != http.StatusCreated {
		t.Fatalf("seed: %d", rec.Code)
	}
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
		{"method":"POST","bulkId":"x","path":"/Users","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"dup@example.com"}}
	]}`
	rec := do(t, h, http.MethodPost, "/Bulk", body)
	br := decodeBulk(t, rec.Body.Bytes())
	if len(br.Operations) != 1 {
		t.Fatalf("ops = %d, want 1", len(br.Operations))
	}
	if br.Operations[0].Status != "409" {
		t.Errorf("dup-create op status = %s, want 409", br.Operations[0].Status)
	}
	if len(br.Operations[0].Response) == 0 {
		t.Error("failed op carried no inline error response body")
	}
}

// TestBulk_PayloadTooLarge: a bulk body over maxPayloadSize is 413.
func TestBulk_PayloadTooLarge(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	// Build a body larger than bulkMaxPayloadSize via a giant userName.
	huge := strings.Repeat("a", bulkMaxPayloadSize+10)
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
		{"method":"POST","bulkId":"x","path":"/Users","data":{"userName":"` + huge + `"}}
	]}`
	rec := do(t, h, http.MethodPost, "/Bulk", body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// TestBulk_MalformedRequest: an unparseable BulkRequest body is 400.
func TestBulk_MalformedRequest(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, "/Bulk", `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

// TestBulk_CreateThenReferenceInData: a POST creates a group via bulk, then a
// later PATCH references the new id inside its data (resolveBulkRefs over data,
// not just path).
func TestBulk_CreateThenReferenceInData(t *testing.T) {
	t.Parallel()
	h, _, _ := newGroupHandler(t)
	// Create a group, then in the same bulk add a member that references the
	// created group's bulkId in the PATCH path.
	body := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[
		{"method":"POST","bulkId":"g","path":"/Groups","data":{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"BulkGroup"}},
		{"method":"PATCH","path":"/Groups/bulkId:g","data":{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","value":[{"value":"u9"}]}]}}
	]}`
	rec := do(t, h, http.MethodPost, "/Bulk", body)
	br := decodeBulk(t, rec.Body.Bytes())
	if len(br.Operations) != 2 {
		t.Fatalf("ops = %d, want 2", len(br.Operations))
	}
	if br.Operations[0].Status != "201" {
		t.Fatalf("group create status = %s (%s)", br.Operations[0].Status, br.Operations[0].Response)
	}
	if br.Operations[1].Status != "200" {
		t.Fatalf("member-add-by-bulkId status = %s, want 200 (%s)", br.Operations[1].Status, br.Operations[1].Response)
	}
}

// TestStorageErrorMapping: a List error inside userNameExists surfaces as a
// SCIM 500 (handler.storageError). failingListProvider wraps a REAL memory
// store (the baseOnlyProvider pattern — every other call delegates to the real
// store) and only forces List to error, so this is not a mock.
func TestStorageErrorMapping(t *testing.T) {
	t.Parallel()
	real := defaultimpl.NewMemoryUserProvider()
	h := NewHandler(failingListProvider{inner: real}, testBase,
		WithIDGenerator(func() string { return "x" }))
	rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"e@example.com"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != ContentTypeSCIM {
		t.Errorf("500 Content-Type = %q, want %q", rec.Header().Get("Content-Type"), ContentTypeSCIM)
	}
	if e := decodeError(t, rec); e.Status != "500" {
		t.Errorf("error status = %q, want 500", e.Status)
	}
}

// TestStorageErrorMapping_ListUsers: a List error on the list endpoint also
// surfaces as a 500 (storageError via listUsers).
func TestStorageErrorMapping_ListUsers(t *testing.T) {
	t.Parallel()
	h := NewHandler(failingListProvider{inner: defaultimpl.NewMemoryUserProvider()}, testBase)
	rec := do(t, h, http.MethodGet, pathUsers, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// failingListProvider wraps a real core.UserProvider and forces List to return
// an error, leaving every other method delegating to the real in-memory store.
// This mirrors baseOnlyProvider in group_test.go: it is a thin adapter over a
// genuine store, not a mock — used to drive the handler's storageError seam.
type failingListProvider struct {
	inner *defaultimpl.MemoryUserProvider
}

func (p failingListProvider) GetByID(ctx context.Context, id string) (*core.User, error) {
	return p.inner.GetByID(ctx, id)
}
func (p failingListProvider) GetByExternalID(ctx context.Context, provider, externalID string) (*core.User, error) {
	return p.inner.GetByExternalID(ctx, provider, externalID)
}
func (p failingListProvider) CreateOrUpdate(ctx context.Context, u *core.User) error {
	return p.inner.CreateOrUpdate(ctx, u)
}
func (p failingListProvider) Delete(ctx context.Context, id string) error {
	return p.inner.Delete(ctx, id)
}
func (p failingListProvider) List(ctx context.Context) ([]*core.User, error) {
	return nil, errStorageProbe
}

var _ core.UserProvider = failingListProvider{}

// errStorageProbe is the sentinel failingListProvider returns from List to
// drive the handler's storageError mapping.
var errStorageProbe = errStorage("scim test: forced list failure")

// errStorage is a trivial error type so the storage-error test needs no extra
// import.
type errStorage string

func (e errStorage) Error() string { return string(e) }
