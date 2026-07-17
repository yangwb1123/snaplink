package adminuser

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// Package adminuser previously shipped with ZERO tests despite backing the
// mutating /api/v1/admin/local-users* admin CRUD surface (docs/error-codes.md
// "Admin user CRUD"). These tests exercise the handlers end-to-end through
// real in-memory implementations (no mocks, per repo convention) rather than
// unit-testing the service functions in isolation, so a wiring regression in
// handlers.go (route param name, status code mapping) is caught the same way
// a real HTTP request would trip it.

// testLogger discards log output (mirrors bgTestLogger in interfaces/admin).
type testLogger struct{}

func (testLogger) Info(string, ...any)  {}
func (testLogger) Error(string, ...any) {}
func (testLogger) Debug(string, ...any) {}

// testDeps is the minimal adminuser.Deps this package's tests need, backed by
// REAL memory implementations (infrastructure/defaultimpl/memorystoreidentity
// + memorystorecredential) rather than mocks.
type testDeps struct {
	users   *memorystoreidentity.MemoryUserProvider
	creds   *memorystorecredential.MemoryPasswordCredentialStore
	auditor *audit.Recorder
	sink    *audit.MemorySink
	metrics *metrics.Metrics
	actorID string
	noCreds bool // simulates a deployment with no PasswordCredentialStore wired
}

func newTestDeps() *testDeps {
	sink := audit.NewMemorySink(100)
	return &testDeps{
		users:   memorystoreidentity.NewMemoryUserProvider(),
		creds:   memorystorecredential.NewMemoryPasswordCredentialStore(),
		auditor: audit.New(sink),
		sink:    sink,
		metrics: metrics.New(),
		actorID: "admin-1",
	}
}

func (d *testDeps) UserProvider() core.UserProvider {
	return d.users
}
func (d *testDeps) PasswordCredentialStore() core.PasswordCredentialStore {
	if d.noCreds {
		return nil
	}
	return d.creds
}
func (d *testDeps) Auditor() *audit.Recorder  { return d.auditor }
func (d *testDeps) Logger() spi.Logger        { return testLogger{} }
func (d *testDeps) Metrics() *metrics.Metrics { return d.metrics }
func (d *testDeps) ActorFromContext(context.Context) (string, string, bool) {
	return d.actorID, "", true
}

// paramCtx layers a :id route param onto a core.Context — StdRouter would
// inject it via path matching in production; tests supply it directly.
// Mirrors gcParamCtx in interfaces/admin/governance_test.go.
type paramCtx struct {
	*core.Context
	id string
}

func (p paramCtx) Param(name string) string {
	if name == "id" {
		return p.id
	}
	return p.Context.Param(name)
}

func newCtx(method, path, id, body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	return paramCtx{Context: core.NewContext(w, r), id: id}, w
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode response body: %v (body=%s)", err, rec.Body.String())
	}
}

func TestHandleAdminCreateUser_Success(t *testing.T) {
	d := newTestDeps()
	ctx, rec := newCtx(http.MethodPost, "/api/v1/admin/local-users", "",
		`{"username":"alice","email":"alice@example.com","password":"correcthorse1"}`)
	HandleAdminCreateUser(d, ctx)
	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d; want 201, body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	decodeBody(t, rec, &resp)
	if resp["username"] != "alice" {
		t.Fatalf("username = %v; want alice", resp["username"])
	}
	if _, leaked := resp["password"]; leaked {
		t.Fatalf("response leaked password field: %v", resp)
	}
	// The password credential must actually be set (not just the user row).
	has, err := d.creds.HasPassword(context.Background(), resp["id"].(string))
	if err != nil || !has {
		t.Fatalf("HasPassword = (%v, %v); want (true, nil)", has, err)
	}
}

func TestHandleAdminCreateUser_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"short username", `{"username":"ab","email":"a@example.com","password":"correcthorse1"}`},
		{"bad email", `{"username":"alice","email":"not-an-email","password":"correcthorse1"}`},
		{"weak password", `{"username":"alice","email":"a@example.com","password":"short"}`},
		{"malformed json", `{"username":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestDeps()
			ctx, rec := newCtx(http.MethodPost, "/api/v1/admin/local-users", "", tc.body)
			HandleAdminCreateUser(d, ctx)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d; want 400, body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHandleAdminCreateUser_UsernameConflict(t *testing.T) {
	d := newTestDeps()
	body := `{"username":"alice","email":"alice@example.com","password":"correcthorse1"}`
	ctx1, rec1 := newCtx(http.MethodPost, "/api/v1/admin/local-users", "", body)
	HandleAdminCreateUser(d, ctx1)
	if rec1.Code != http.StatusCreated {
		t.Fatalf("first create code = %d; want 201, body=%s", rec1.Code, rec1.Body.String())
	}
	ctx2, rec2 := newCtx(http.MethodPost, "/api/v1/admin/local-users", "",
		`{"username":"alice","email":"someone-else@example.com","password":"correcthorse1"}`)
	HandleAdminCreateUser(d, ctx2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second create code = %d; want 409, body=%s", rec2.Code, rec2.Body.String())
	}
	var errBody map[string]any
	decodeBody(t, rec2, &errBody)
	if errBody["error"] != core.ErrUserConflict {
		t.Fatalf("error = %v; want %s", errBody["error"], core.ErrUserConflict)
	}
}

func createTestUser(t *testing.T, d *testDeps, username, email string) string {
	t.Helper()
	ctx, rec := newCtx(http.MethodPost, "/api/v1/admin/local-users", "",
		`{"username":"`+username+`","email":"`+email+`","password":"correcthorse1"}`)
	HandleAdminCreateUser(d, ctx)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user code = %d; want 201, body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	decodeBody(t, rec, &resp)
	return resp["id"].(string)
}

func TestHandleAdminGetUser(t *testing.T) {
	d := newTestDeps()
	id := createTestUser(t, d, "bob", "bob@example.com")

	ctx, rec := newCtx(http.MethodGet, "/api/v1/admin/local-users/"+id, id, "")
	HandleAdminGetUser(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d; want 200, body=%s", rec.Code, rec.Body.String())
	}

	missingCtx, missingRec := newCtx(http.MethodGet, "/api/v1/admin/local-users/nope", "nope", "")
	HandleAdminGetUser(d, missingCtx)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("unknown user code = %d; want 404, body=%s", missingRec.Code, missingRec.Body.String())
	}

	blankCtx, blankRec := newCtx(http.MethodGet, "/api/v1/admin/local-users/", "", "")
	HandleAdminGetUser(d, blankCtx)
	if blankRec.Code != http.StatusBadRequest {
		t.Fatalf("blank id code = %d; want 400, body=%s", blankRec.Code, blankRec.Body.String())
	}
}

func TestHandleAdminUpdateUser(t *testing.T) {
	d := newTestDeps()
	id1 := createTestUser(t, d, "carol", "carol@example.com")
	id2 := createTestUser(t, d, "dave", "dave@example.com")

	// Not found.
	nfCtx, nfRec := newCtx(http.MethodPut, "/api/v1/admin/local-users/nope", "nope", `{"display_name":"X"}`)
	HandleAdminUpdateUser(d, nfCtx)
	if nfRec.Code != http.StatusNotFound {
		t.Fatalf("code = %d; want 404, body=%s", nfRec.Code, nfRec.Body.String())
	}

	// Email conflict: id2 tries to take id1's email.
	conflictCtx, conflictRec := newCtx(http.MethodPut, "/api/v1/admin/local-users/"+id2, id2,
		`{"email":"carol@example.com"}`)
	HandleAdminUpdateUser(d, conflictCtx)
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("code = %d; want 409, body=%s", conflictRec.Code, conflictRec.Body.String())
	}

	// Invalid email format.
	badCtx, badRec := newCtx(http.MethodPut, "/api/v1/admin/local-users/"+id1, id1, `{"email":"not-an-email"}`)
	HandleAdminUpdateUser(d, badCtx)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d; want 400, body=%s", badRec.Code, badRec.Body.String())
	}

	// Successful update.
	okCtx, okRec := newCtx(http.MethodPut, "/api/v1/admin/local-users/"+id1, id1,
		`{"display_name":"Carol Danvers"}`)
	HandleAdminUpdateUser(d, okCtx)
	if okRec.Code != http.StatusOK {
		t.Fatalf("code = %d; want 200, body=%s", okRec.Code, okRec.Body.String())
	}
	var resp map[string]any
	decodeBody(t, okRec, &resp)
	if resp["display_name"] != "Carol Danvers" {
		t.Fatalf("display_name = %v; want Carol Danvers", resp["display_name"])
	}
}

// TestHandleAdminDeleteUser_RemovesPasswordCredential is the regression test
// for the bug this change fixes: DeleteUser's doc comment promised
// "best-effort" removal of the user's password credential, but the service
// function never actually touched the PasswordCredentialStore, leaving an
// orphaned bcrypt hash behind forever. It now type-asserts for the optional
// core.PasswordCredentialDeleter extension (which MemoryPasswordCredentialStore
// implements) and calls it.
func TestHandleAdminDeleteUser_RemovesPasswordCredential(t *testing.T) {
	d := newTestDeps()
	id := createTestUser(t, d, "erin", "erin@example.com")

	has, err := d.creds.HasPassword(context.Background(), id)
	if err != nil || !has {
		t.Fatalf("precondition: HasPassword = (%v, %v); want (true, nil)", has, err)
	}

	ctx, rec := newCtx(http.MethodDelete, "/api/v1/admin/local-users/"+id, id, "")
	HandleAdminDeleteUser(d, ctx)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d; want 204, body=%s", rec.Code, rec.Body.String())
	}

	// The user row is gone.
	if _, err := d.users.GetByID(context.Background(), id); err == nil {
		t.Fatalf("user %s still resolves after delete", id)
	}

	// The orphaned credential must be gone too — this is the fix.
	has, err = d.creds.HasPassword(context.Background(), id)
	if err != nil {
		t.Fatalf("HasPassword after delete: %v", err)
	}
	if has {
		t.Fatalf("password credential for deleted user %s was NOT removed (leaked, unreachable hash)", id)
	}
}

// TestHandleAdminDeleteUser_NoCredentialStoreWired proves the credential
// cleanup is best-effort: a deployment with no PasswordCredentialStore wired
// at all must still delete the user cleanly (byte-identical to before this
// change for that configuration).
func TestHandleAdminDeleteUser_NoCredentialStoreWired(t *testing.T) {
	d := newTestDeps()
	id := createTestUser(t, d, "frank", "frank@example.com")
	d.noCreds = true

	ctx, rec := newCtx(http.MethodDelete, "/api/v1/admin/local-users/"+id, id, "")
	HandleAdminDeleteUser(d, ctx)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code = %d; want 204, body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleAdminDeleteUser_IdempotentAndValidation(t *testing.T) {
	d := newTestDeps()
	id := createTestUser(t, d, "grace", "grace@example.com")

	ctx1, rec1 := newCtx(http.MethodDelete, "/api/v1/admin/local-users/"+id, id, "")
	HandleAdminDeleteUser(d, ctx1)
	if rec1.Code != http.StatusNoContent {
		t.Fatalf("first delete code = %d; want 204", rec1.Code)
	}
	// Deleting again (or an unknown id) is idempotent — still 204.
	ctx2, rec2 := newCtx(http.MethodDelete, "/api/v1/admin/local-users/"+id, id, "")
	HandleAdminDeleteUser(d, ctx2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second delete code = %d; want 204 (idempotent)", rec2.Code)
	}

	blankCtx, blankRec := newCtx(http.MethodDelete, "/api/v1/admin/local-users/", "", "")
	HandleAdminDeleteUser(d, blankCtx)
	if blankRec.Code != http.StatusBadRequest {
		t.Fatalf("blank id code = %d; want 400", blankRec.Code)
	}
}

func TestHandleAdminListUsers(t *testing.T) {
	d := newTestDeps()
	createTestUser(t, d, "user1", "user1@example.com")
	createTestUser(t, d, "user2", "user2@example.com")
	createTestUser(t, d, "user3", "user3@example.com")

	ctx, rec := newCtx(http.MethodGet, "/api/v1/admin/local-users?page=1&limit=2", "", "")
	HandleAdminListUsers(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d; want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	decodeBody(t, rec, &resp)
	if int(resp["total"].(float64)) != 3 {
		t.Fatalf("total = %v; want 3", resp["total"])
	}
	users, _ := resp["users"].([]any)
	if len(users) != 2 {
		t.Fatalf("len(users) = %d; want 2 (limit)", len(users))
	}
}

func TestHandleAdminListUsers_InvalidPagination(t *testing.T) {
	cases := []string{"?page=0", "?page=abc", "?limit=0", "?limit=101", "?limit=abc"}
	for _, q := range cases {
		t.Run(q, func(t *testing.T) {
			d := newTestDeps()
			ctx, rec := newCtx(http.MethodGet, "/api/v1/admin/local-users"+q, "", "")
			HandleAdminListUsers(d, ctx)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code = %d; want 400, body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
