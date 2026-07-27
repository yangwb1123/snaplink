package permissions_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// handlerDeps is the in-test wiring of permissions.HandlerDeps. No mocks:
// the Provider is a real *MemoryProvider (or the failing variant below,
// built from real types), the Recorder is a real audit.Recorder backed by
// a MemorySink, and the subject is supplied verbatim.
type handlerDeps struct {
	prov    permissions.Provider
	rec     *audit.Recorder
	userID  string
	clientD string
	authOK  bool
}

func (d handlerDeps) Permissions() permissions.Provider { return d.prov }
func (d handlerDeps) SrvLogger() spi.Logger             { return spi.NopLogger{} }
func (d handlerDeps) Auditor() *audit.Recorder          { return d.rec }
func (d handlerDeps) AuthenticatedSubject(_ core.HandlerContext) (string, string, bool) {
	return d.userID, d.clientD, d.authOK
}

// failingProvider wraps a Provider but forces the read methods to return a
// hard (non-ErrUserNotFound) error so the handlers' 500 branches run.
type failingProvider struct {
	permissions.Provider
	err error
}

func (f failingProvider) Permissions(context.Context, string, string) ([]permissions.Permission, error) {
	return nil, f.err
}
func (f failingProvider) Roles(context.Context, string, string) ([]permissions.Role, error) {
	return nil, f.err
}
func (f failingProvider) Menus(context.Context, string, string) (permissions.MenuTree, error) {
	return nil, f.err
}

// nilMenuProvider returns a nil MenuTree with NO error, so HandleMyMenus
// runs its `menus == nil → MenuTree{}` normalization branch (the
// MemoryProvider always hands back a non-nil empty tree, so that branch
// is otherwise unreachable through the real backend).
type nilMenuProvider struct{ *permissions.MemoryProvider }

func (nilMenuProvider) Menus(context.Context, string, string) (permissions.MenuTree, error) {
	return nil, nil
}

func newHandlerCtx(t *testing.T) (*core.Context, *httptest.ResponseRecorder) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
	return core.NewContext(rr, req), rr
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode body %q: %v", rr.Body.String(), err)
	}
	return m
}

// queryEvents reads back what RecordQuery wrote, proving the audit side
// effect actually fired (and with the right outcome).
func queryEvents(t *testing.T, rec *audit.Recorder) []*audit.Event {
	t.Helper()
	evs, err := rec.Sink().Query(context.Background(), audit.Query{Type: audit.EventPermissionQuery})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return evs
}

func TestHandleMyPermissions_Success(t *testing.T) {
	t.Parallel()
	p := fixture(t)
	rec := audit.New(audit.NewMemorySink(16))
	d := handlerDeps{prov: p, rec: rec, userID: "user-alice", clientD: "web-app", authOK: true}

	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyPermissions(d, ctx)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body[core.KeyClient] != "web-app" {
		t.Errorf("client_id=%v", body[core.KeyClient])
	}
	perms, ok := body[core.KeyPermissions].([]any)
	if !ok || len(perms) == 0 {
		t.Errorf("expected non-empty permissions, got %v", body[core.KeyPermissions])
	}
	if evs := queryEvents(t, rec); len(evs) != 1 || evs[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("expected one success audit event, got %+v", evs)
	}
}

func TestHandleMyPermissions_UnauthenticatedNoOp(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: permissions.NewMemoryProvider(), rec: audit.New(audit.NewMemorySink(4)), authOK: false}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyPermissions(d, ctx)
	// AuthenticatedSubject==false → handler returns before writing anything.
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("expected no write, got status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestHandleMyPermissions_NilProvider501(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: nil, rec: nil, userID: "u", clientD: "c", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyPermissions(d, ctx)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d want 501", rr.Code)
	}
	if decodeBody(t, rr)[core.KeyError] != core.ErrPermissionProviderNotConfigured {
		t.Errorf("body=%s", rr.Body.String())
	}
}

func TestHandleMyPermissions_LookupError500(t *testing.T) {
	t.Parallel()
	rec := audit.New(audit.NewMemorySink(4))
	d := handlerDeps{
		prov:    failingProvider{Provider: permissions.NewMemoryProvider(), err: errors.New("boom")},
		rec:     rec,
		userID:  "u",
		clientD: "c",
		authOK:  true,
	}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyPermissions(d, ctx)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", rr.Code)
	}
	if decodeBody(t, rr)[core.KeyError] != core.ErrPermissionLookupFailed {
		t.Errorf("body=%s", rr.Body.String())
	}
	if evs := queryEvents(t, rec); len(evs) != 1 || evs[0].Outcome != audit.OutcomeFailure {
		t.Errorf("expected one failure audit event, got %+v", evs)
	}
}

func TestHandleMyPermissions_UnknownUserStillOK(t *testing.T) {
	t.Parallel()
	// ErrUserNotFound is swallowed: the handler returns an empty list + 200,
	// not a 500 (anti-enumeration / UX).
	p := permissions.NewMemoryProvider()
	d := handlerDeps{prov: p, rec: audit.New(audit.NewMemorySink(4)), userID: "ghost", clientD: "c", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyPermissions(d, ctx)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	perms := decodeBody(t, rr)[core.KeyPermissions]
	if arr, ok := perms.([]any); !ok || len(arr) != 0 {
		t.Errorf("expected empty permissions array, got %v", perms)
	}
}

func TestHandleMyRoles_Success(t *testing.T) {
	t.Parallel()
	p := fixture(t)
	rec := audit.New(audit.NewMemorySink(8))
	d := handlerDeps{prov: p, rec: rec, userID: "user-alice", clientD: "web-app", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyRoles(d, ctx)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	roles, ok := decodeBody(t, rr)[core.KeyRoles].([]any)
	if !ok || len(roles) != 1 {
		t.Errorf("roles=%v", decodeBody(t, rr)[core.KeyRoles])
	}
}

func TestHandleMyRoles_NilProvider501(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: nil, userID: "u", clientD: "c", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyRoles(d, ctx)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d want 501", rr.Code)
	}
}

func TestHandleMyRoles_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: permissions.NewMemoryProvider(), authOK: false}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyRoles(d, ctx)
	if rr.Body.Len() != 0 {
		t.Fatalf("expected no body, got %q", rr.Body.String())
	}
}

func TestHandleMyRoles_LookupError500(t *testing.T) {
	t.Parallel()
	rec := audit.New(audit.NewMemorySink(4))
	d := handlerDeps{
		prov:    failingProvider{Provider: permissions.NewMemoryProvider(), err: errors.New("boom")},
		rec:     rec,
		userID:  "u",
		clientD: "c",
		authOK:  true,
	}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyRoles(d, ctx)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", rr.Code)
	}
	if evs := queryEvents(t, rec); len(evs) != 1 || evs[0].Outcome != audit.OutcomeFailure {
		t.Errorf("expected failure audit, got %+v", evs)
	}
}

func TestHandleMyRoles_UnknownUserEmptyOK(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: permissions.NewMemoryProvider(), rec: audit.New(audit.NewMemorySink(4)), userID: "ghost", clientD: "c", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyRoles(d, ctx)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	if arr, ok := decodeBody(t, rr)[core.KeyRoles].([]any); !ok || len(arr) != 0 {
		t.Errorf("expected empty roles, got %v", decodeBody(t, rr)[core.KeyRoles])
	}
}

func TestHandleMyMenus_Success(t *testing.T) {
	t.Parallel()
	p := fixture(t)
	rec := audit.New(audit.NewMemorySink(8))
	d := handlerDeps{prov: p, rec: rec, userID: "user-alice", clientD: "web-app", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyMenus(d, ctx)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	if _, ok := decodeBody(t, rr)[core.KeyMenus]; !ok {
		t.Errorf("menus key missing: %s", rr.Body.String())
	}
}

func TestHandleMyMenus_NilProvider501(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: nil, userID: "u", clientD: "c", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyMenus(d, ctx)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d want 501", rr.Code)
	}
}

func TestHandleMyMenus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := handlerDeps{prov: permissions.NewMemoryProvider(), authOK: false}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyMenus(d, ctx)
	if rr.Body.Len() != 0 {
		t.Fatalf("expected no body, got %q", rr.Body.String())
	}
}

func TestHandleMyMenus_LookupError500(t *testing.T) {
	t.Parallel()
	// Menus has no ErrUserNotFound short-circuit — ANY error is a 500.
	rec := audit.New(audit.NewMemorySink(4))
	d := handlerDeps{
		prov:    failingProvider{Provider: permissions.NewMemoryProvider(), err: errors.New("boom")},
		rec:     rec,
		userID:  "u",
		clientD: "c",
		authOK:  true,
	}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyMenus(d, ctx)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", rr.Code)
	}
	if evs := queryEvents(t, rec); len(evs) != 1 || evs[0].Outcome != audit.OutcomeFailure {
		t.Errorf("expected failure audit, got %+v", evs)
	}
}

func TestHandleMyMenus_EmptyMenusOK(t *testing.T) {
	t.Parallel()
	// Unknown user → Provider.Menus returns an empty tree (not error) → 200.
	d := handlerDeps{prov: permissions.NewMemoryProvider(), rec: audit.New(audit.NewMemorySink(4)), userID: "ghost", clientD: "c", authOK: true}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyMenus(d, ctx)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
}

func TestHandleMyMenus_NilTreeNormalizedToEmpty(t *testing.T) {
	t.Parallel()
	// Provider returns (nil, nil): the handler must normalize the nil tree
	// to an empty MenuTree{} and still return 200 with a menus key.
	d := handlerDeps{
		prov:    nilMenuProvider{MemoryProvider: permissions.NewMemoryProvider()},
		rec:     audit.New(audit.NewMemorySink(4)),
		userID:  "u",
		clientD: "c",
		authOK:  true,
	}
	ctx, rr := newHandlerCtx(t)
	permissions.HandleMyMenus(d, ctx)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", rr.Code, rr.Body.String())
	}
	menus, ok := decodeBody(t, rr)[core.KeyMenus]
	if !ok {
		t.Fatalf("menus key missing")
	}
	if arr, ok := menus.([]any); !ok || len(arr) != 0 {
		t.Errorf("expected empty menus array, got %v", menus)
	}
}

func TestResolveForLogin_NilProviderReturnsNils(t *testing.T) {
	t.Parallel()
	roles, perms, menus := permissions.ResolveForLogin(nil, spi.NopLogger{}, context.Background(), "u", "c")
	if roles != nil || perms != nil || menus != nil {
		t.Fatalf("nil provider should yield nils, got %v / %v / %v", roles, perms, menus)
	}
}

func TestResolveForLogin_PopulatesBundle(t *testing.T) {
	t.Parallel()
	p := fixture(t)
	roles, perms, menus := permissions.ResolveForLogin(p, spi.NopLogger{}, context.Background(), "user-alice", "web-app")
	if len(roles) != 1 {
		t.Errorf("roles=%v", roles)
	}
	if len(perms) == 0 {
		t.Errorf("expected non-empty perms")
	}
	if len(menus) == 0 {
		t.Errorf("expected non-empty menus")
	}
}

func TestResolveForLogin_UnknownUserSwallowsErr(t *testing.T) {
	t.Parallel()
	// ErrUserNotFound is swallowed for roles+perms; Menus returns empty.
	// The function never errors out a login.
	p := fixture(t)
	roles, perms, menus := permissions.ResolveForLogin(p, spi.NopLogger{}, context.Background(), "ghost", "web-app")
	if len(roles) != 0 || len(perms) != 0 || len(menus) != 0 {
		t.Fatalf("unknown user should yield empties, got %v / %v / %v", roles, perms, menus)
	}
}

func TestResolveForLogin_HardErrorsLoggedNotFatal(t *testing.T) {
	t.Parallel()
	// A non-ErrUserNotFound error from every read is logged and the
	// function still returns (empty bundle) so login proceeds.
	fp := failingProvider{Provider: permissions.NewMemoryProvider(), err: errors.New("backend down")}
	roles, perms, menus := permissions.ResolveForLogin(fp, spi.NopLogger{}, context.Background(), "u", "c")
	if roles != nil || perms != nil || menus != nil {
		t.Fatalf("expected nil bundle on hard error, got %v / %v / %v", roles, perms, menus)
	}
}

func TestRecordQuery_NilRecorderNoPanic(t *testing.T) {
	t.Parallel()
	// Audit is opt-in: a nil recorder must be a safe no-op.
	ctx, _ := newHandlerCtx(t)
	permissions.RecordQuery(nil, ctx, "u", "c", core.KeyPermissions, true)
}

func TestRecordQuery_StampsFields(t *testing.T) {
	t.Parallel()
	rec := audit.New(audit.NewMemorySink(4))
	ctx, _ := newHandlerCtx(t)
	permissions.RecordQuery(rec, ctx, "user-x", "client-y", core.KeyMenus, false)

	evs := queryEvents(t, rec)
	if len(evs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(evs))
	}
	e := evs[0]
	if e.ActorID != "user-x" || e.ClientID != "client-y" {
		t.Errorf("actor/client = %q/%q", e.ActorID, e.ClientID)
	}
	if e.Outcome != audit.OutcomeFailure {
		t.Errorf("outcome=%q want failure", e.Outcome)
	}
	if e.Metadata["kind"] != core.KeyMenus {
		t.Errorf("kind meta = %q", e.Metadata["kind"])
	}
}
