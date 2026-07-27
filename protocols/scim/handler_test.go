package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

const testBase = "/api/v1/scim/v2"

// newTestHandler builds a Handler over a real MemoryUserProvider (no
// mocks per repo convention) with a deterministic id generator + clock so
// assertions on id and meta timestamps are stable.
func newTestHandler(t *testing.T) (*Handler, *defaultimpl.MemoryUserProvider, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	sink := audit.NewMemorySink(64)
	var seq int
	gen := func() string {
		seq++
		return fmt.Sprintf("id-%d", seq)
	}
	fixed := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	h := NewHandler(users, testBase,
		WithRecorder(audit.New(sink)),
		WithIDGenerator(gen),
		WithClock(func() time.Time { return fixed }),
	)
	return h, users, sink
}

// do issues a request against the handler and returns the recorder.
func do(t *testing.T, h *Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, testBase+path, nil)
	} else {
		r = httptest.NewRequest(method, testBase+path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func decodeResource(t *testing.T, rec *httptest.ResponseRecorder) Resource {
	t.Helper()
	var res Resource
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode resource: %v; body=%s", err, rec.Body.String())
	}
	return res
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var e ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode error: %v; body=%s", err, rec.Body.String())
	}
	return e
}

// TestUserRoundTrip exercises create -> get -> list -> replace -> delete,
// verifying the SCIM representation survives the trip through core.User.
func TestUserRoundTrip(t *testing.T) {
	t.Parallel()
	h, _, sink := newTestHandler(t)

	// --- create ---
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "alice@example.com",
		"externalId": "ext-alice",
		"name": {"givenName": "Alice", "familyName": "Smith", "formatted": "Alice Smith"},
		"displayName": "Alice Smith",
		"emails": [
			{"value": "alice@example.com", "type": "work", "primary": true},
			{"value": "alice@home.example", "type": "home"}
		],
		"active": true
	}`
	rec := do(t, h, http.MethodPost, pathUsers, createBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != ContentTypeSCIM {
		t.Errorf("create Content-Type = %q, want %q", ct, ContentTypeSCIM)
	}
	created := decodeResource(t, rec)
	if created.ID != "id-1" {
		t.Fatalf("created id = %q, want id-1", created.ID)
	}
	if created.UserName != "alice@example.com" {
		t.Errorf("userName = %q", created.UserName)
	}
	if created.ExternalID != "ext-alice" {
		t.Errorf("externalId = %q", created.ExternalID)
	}
	if created.Name == nil || created.Name.GivenName != "Alice" || created.Name.FamilyName != "Smith" {
		t.Errorf("name not round-tripped: %+v", created.Name)
	}
	if !created.Active {
		t.Error("active = false, want true")
	}
	if got, want := len(created.Schemas), 1; got != want || created.Schemas[0] != SchemaUser {
		t.Errorf("schemas = %v", created.Schemas)
	}
	// meta: resourceType + location + created/lastModified stamped.
	if created.Meta == nil || created.Meta.ResourceType != resourceTypeUser {
		t.Fatalf("meta missing/wrong: %+v", created.Meta)
	}
	wantLoc := testBase + pathUsers + "/id-1"
	if created.Meta.Location != wantLoc {
		t.Errorf("meta.location = %q, want %q", created.Meta.Location, wantLoc)
	}
	if created.Meta.Created == "" || created.Meta.LastModified == "" {
		t.Errorf("meta timestamps missing: %+v", created.Meta)
	}
	// Both emails preserved (primary from Email, extra from Attributes).
	if len(created.Emails) != 2 {
		t.Fatalf("emails len = %d, want 2: %+v", len(created.Emails), created.Emails)
	}
	if created.primaryEmail() != "alice@example.com" {
		t.Errorf("primary email = %q", created.primaryEmail())
	}
	assertSubjectAudited(t, sink, audit.EventAdminUserCreated, "id-1")

	// --- get ---
	rec = do(t, h, http.MethodGet, pathUsers+"/id-1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", rec.Code)
	}
	got := decodeResource(t, rec)
	if got.UserName != "alice@example.com" || got.ExternalID != "ext-alice" {
		t.Errorf("get mismatch: %+v", got)
	}

	// --- list ---
	rec = do(t, h, http.MethodGet, pathUsers, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", rec.Code)
	}
	var lr ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(lr.Schemas) != 1 || lr.Schemas[0] != SchemaListResponse {
		t.Errorf("list schemas = %v, want [%s]", lr.Schemas, SchemaListResponse)
	}
	if lr.TotalResults != 1 || lr.StartIndex != 1 || lr.ItemsPerPage != 1 {
		t.Errorf("list envelope = total %d start %d per %d", lr.TotalResults, lr.StartIndex, lr.ItemsPerPage)
	}
	if len(lr.Resources) != 1 || lr.Resources[0].ID != "id-1" {
		t.Errorf("list resources = %+v", lr.Resources)
	}

	// --- replace ---
	replaceBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "alice2@example.com",
		"displayName": "Alice Two",
		"active": false
	}`
	rec = do(t, h, http.MethodPut, pathUsers+"/id-1", replaceBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("replace status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	replaced := decodeResource(t, rec)
	if replaced.UserName != "alice2@example.com" {
		t.Errorf("replaced userName = %q", replaced.UserName)
	}
	if replaced.Active {
		t.Error("replaced active = true, want false")
	}
	// Replace is a full overwrite: the old externalId/name must be gone.
	if replaced.ExternalID != "" {
		t.Errorf("replace did not clear externalId: %q", replaced.ExternalID)
	}
	if replaced.Name != nil {
		t.Errorf("replace did not clear name: %+v", replaced.Name)
	}
	assertSubjectAudited(t, sink, audit.EventAdminUserUpdated, "id-1")

	// --- delete ---
	rec = do(t, h, http.MethodDelete, pathUsers+"/id-1", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", rec.Code)
	}
	assertSubjectAudited(t, sink, audit.EventAdminUserDeleted, "id-1")

	// gone now
	rec = do(t, h, http.MethodGet, pathUsers+"/id-1", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete status = %d, want 404", rec.Code)
	}
}

func TestCreate_MissingUserName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, pathUsers, `{"displayName":"No Name"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	e := decodeError(t, rec)
	if len(e.Schemas) != 1 || e.Schemas[0] != SchemaError {
		t.Errorf("error schemas = %v, want [%s]", e.Schemas, SchemaError)
	}
	if e.Status != "400" {
		t.Errorf("error status = %q, want \"400\"", e.Status)
	}
	if e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

func TestCreate_BadJSON(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPost, pathUsers, `{not json`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	e := decodeError(t, rec)
	if e.ScimType != scimTypeInvalidSyntax {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidSyntax)
	}
}

func TestCreate_DuplicateUserName(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	body := `{"userName":"dup@example.com"}`
	if rec := do(t, h, http.MethodPost, pathUsers, body); rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201", rec.Code)
	}
	rec := do(t, h, http.MethodPost, pathUsers, body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("dup create status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	e := decodeError(t, rec)
	if e.ScimType != scimTypeUniqueness {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeUniqueness)
	}
	if e.Status != "409" {
		t.Errorf("status = %q, want \"409\"", e.Status)
	}
}

func TestGet_NotFound(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathUsers+"/nope", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	e := decodeError(t, rec)
	if e.Status != "404" || len(e.Schemas) != 1 || e.Schemas[0] != SchemaError {
		t.Errorf("error shape wrong: %+v", e)
	}
}

func TestReplace_NotFoundIsNotUpsert(t *testing.T) {
	t.Parallel()
	h, users, _ := newTestHandler(t)
	rec := do(t, h, http.MethodPut, pathUsers+"/ghost", `{"userName":"ghost@example.com"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (PUT must not upsert)", rec.Code)
	}
	// Confirm nothing was written.
	if _, err := users.GetByID(context.Background(), "ghost"); err == nil {
		t.Error("PUT to unknown id created a user (must be 404, no write)")
	}
}

func TestReplace_ImmutableID(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	if rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"a@example.com"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d", rec.Code)
	}
	// Body carries a DIFFERENT id than the path -> mutability violation.
	rec := do(t, h, http.MethodPut, pathUsers+"/id-1",
		`{"id":"id-999","userName":"a@example.com"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	e := decodeError(t, rec)
	if e.ScimType != scimTypeMutability {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeMutability)
	}
}

func TestDelete_NotFound(t *testing.T) {
	t.Parallel()
	h, _, sink := newTestHandler(t)
	rec := do(t, h, http.MethodDelete, pathUsers+"/missing", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	// A 404 delete must NOT emit a deletion audit event.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventAdminUserDeleted})
	if len(events) != 0 {
		t.Errorf("404 delete emitted %d delete events, want 0", len(events))
	}
}

// TestListPagination verifies the 1-based startIndex/count slicing and the
// ListResponse envelope counts.
func TestListPagination(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	for i := 0; i < 5; i++ {
		body := fmt.Sprintf(`{"userName":"u%d@example.com"}`, i)
		if rec := do(t, h, http.MethodPost, pathUsers, body); rec.Code != http.StatusCreated {
			t.Fatalf("seed %d status = %d", i, rec.Code)
		}
	}

	// Page 2, size 2 -> startIndex=3, count=2 -> 2 items, total still 5.
	rec := do(t, h, http.MethodGet, pathUsers+"?startIndex=3&count=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var lr ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 5 {
		t.Errorf("totalResults = %d, want 5", lr.TotalResults)
	}
	if lr.StartIndex != 3 {
		t.Errorf("startIndex = %d, want 3", lr.StartIndex)
	}
	if lr.ItemsPerPage != 2 || len(lr.Resources) != 2 {
		t.Errorf("itemsPerPage = %d, resources = %d, want 2/2", lr.ItemsPerPage, len(lr.Resources))
	}

	// startIndex past the end -> empty page, total preserved.
	rec = do(t, h, http.MethodGet, pathUsers+"?startIndex=99&count=10", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 5 || len(lr.Resources) != 0 || lr.ItemsPerPage != 0 {
		t.Errorf("out-of-range page: total %d items %d per %d", lr.TotalResults, len(lr.Resources), lr.ItemsPerPage)
	}

	// count=0 -> just the count, no resources (RFC 7644 §3.4.2.4).
	rec = do(t, h, http.MethodGet, pathUsers+"?count=0", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &lr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if lr.TotalResults != 5 || len(lr.Resources) != 0 {
		t.Errorf("count=0: total %d items %d", lr.TotalResults, len(lr.Resources))
	}
}

func TestListPagination_BadParam(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathUsers+"?count=abc", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if e := decodeError(t, rec); e.ScimType != scimTypeInvalidValue {
		t.Errorf("scimType = %q, want %q", e.ScimType, scimTypeInvalidValue)
	}
}

func TestActiveDefaultsTrueOnCreate(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	// Body omits "active" -> provisioned account must be active.
	rec := do(t, h, http.MethodPost, pathUsers, `{"userName":"a@example.com"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d", rec.Code)
	}
	if !decodeResource(t, rec).Active {
		t.Error("active defaulted to false; want true when omitted")
	}
}

func TestServiceProviderConfig(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathServiceProviderConfig, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var cfg ServiceProviderConfig
	if err := json.Unmarshal(rec.Body.Bytes(), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cfg.Schemas) != 1 || cfg.Schemas[0] != SchemaServiceProviderConfig {
		t.Errorf("schemas = %v", cfg.Schemas)
	}
	// PATCH (RFC 7644 §3.5.2), filtering (§3.4.2.2), and bulk (§3.7) are all
	// implemented so each MUST advertise true.
	if !cfg.Patch.Supported {
		t.Error("patch advertised unsupported, want supported (RFC 7644 §3.5.2 implemented)")
	}
	if !cfg.Filter.Supported {
		t.Error("filter advertised unsupported, want supported (RFC 7644 §3.4.2.2 implemented)")
	}
	if cfg.Filter.MaxResults != filterMaxResults {
		t.Errorf("filter.maxResults = %d, want %d", cfg.Filter.MaxResults, filterMaxResults)
	}
	if !cfg.Bulk.Supported {
		t.Error("bulk advertised unsupported, want supported (RFC 7644 §3.7 implemented)")
	}
	if cfg.Bulk.MaxOperations != bulkMaxOperations || cfg.Bulk.MaxPayloadSize != bulkMaxPayloadSize {
		t.Errorf("bulk limits = %d/%d, want %d/%d", cfg.Bulk.MaxOperations, cfg.Bulk.MaxPayloadSize, bulkMaxOperations, bulkMaxPayloadSize)
	}
	// Sort (RFC 7644 §3.4.2.3) and ETag/conditional requests (§3.14) are
	// implemented so both MUST advertise true.
	if !cfg.Sort.Supported {
		t.Error("sort advertised unsupported, want supported (RFC 7644 §3.4.2.3 implemented)")
	}
	if !cfg.ETag.Supported {
		t.Error("etag advertised unsupported, want supported (RFC 7644 §3.14 implemented)")
	}
	if len(cfg.AuthenticationSchemes) == 0 {
		t.Error("no authentication schemes advertised")
	}
}

func TestSchemas(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathSchemas, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var env struct {
		Schemas      []string         `json:"schemas"`
		TotalResults int              `json:"totalResults"`
		Resources    []SchemaResource `json:"Resources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(env.Schemas) != 1 || env.Schemas[0] != SchemaListResponse {
		t.Errorf("envelope schemas = %v", env.Schemas)
	}
	if env.TotalResults != 1 || len(env.Resources) != 1 {
		t.Fatalf("schemas total = %d, resources = %d", env.TotalResults, len(env.Resources))
	}
	if env.Resources[0].ID != SchemaUser {
		t.Errorf("schema id = %q, want %q", env.Resources[0].ID, SchemaUser)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	// DELETE on the collection is not defined.
	rec := do(t, h, http.MethodDelete, pathUsers, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestUnknownEndpoint(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, "/Groups", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestNestedUserPath confirms ".../Users/a/b" is treated as not-found
// rather than misrouted as a single id.
func TestNestedUserPath(t *testing.T) {
	t.Parallel()
	h, _, _ := newTestHandler(t)
	rec := do(t, h, http.MethodGet, pathUsers+"/a/b", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestExistingNonSCIMUserReadsActive verifies a user created OUTSIDE SCIM
// (no scim:active attribute) reads back as active=true, so the admin API
// and SCIM agree on enabled accounts.
func TestExistingNonSCIMUserReadsActive(t *testing.T) {
	t.Parallel()
	h, users, _ := newTestHandler(t)
	if err := users.CreateOrUpdate(context.Background(), &core.User{
		ID:    "admin-made",
		Email: "x@example.com",
		Name:  "X",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := do(t, h, http.MethodGet, pathUsers+"/admin-made", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	res := decodeResource(t, rec)
	if !res.Active {
		t.Error("non-SCIM user read as inactive; want active=true default")
	}
	if res.DisplayName != "X" {
		t.Errorf("displayName = %q, want X", res.DisplayName)
	}
}

func assertSubjectAudited(t *testing.T, sink *audit.MemorySink, typ audit.EventType, subject string) {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{Type: typ})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	for _, e := range events {
		if e.Metadata["subject"] == subject {
			if e.Metadata["via"] != "scim" {
				t.Errorf("audit %q missing via=scim metadata: %v", typ, e.Metadata)
			}
			return
		}
	}
	t.Errorf("no %q audit event for subject %q (have %d events)", typ, subject, len(events))
}
