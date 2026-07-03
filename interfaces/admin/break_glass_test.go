package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// Break-glass handler tests exercise the real Memory* implementations end to
// end (no mocks, per repo convention): memorystoreidentity.MemoryBreakGlassStore,
// memorystoreidentity.MemorySessionManager, and a real audit.Recorder over
// audit.NewMemorySink so the SOC 2 evidence-chain metadata can be asserted
// from the actual recorded events, not a stubbed expectation.

// bgTestLogger discards log output.
type bgTestLogger struct{}

func (bgTestLogger) Info(string, ...any)  {}
func (bgTestLogger) Error(string, ...any) {}
func (bgTestLogger) Debug(string, ...any) {}

// bgTestDeps is the minimal admin.Deps break-glass tests need. Every method
// break-glass doesn't touch returns its zero value — it's the same shape
// production wiring uses when a store is simply not configured.
type bgTestDeps struct {
	sessions   core.SessionManager
	breakGlass core.BreakGlassStore
	auditor    *audit.Recorder
}

func (d *bgTestDeps) SessionMgr() core.SessionManager                       { return d.sessions }
func (d *bgTestDeps) BreakGlassStore() core.BreakGlassStore                 { return d.breakGlass }
func (d *bgTestDeps) Auditor() *audit.Recorder                              { return d.auditor }
func (d *bgTestDeps) Logger() spi.Logger                                    { return bgTestLogger{} }
func (d *bgTestDeps) ConnectionStore() connections.Store                    { return nil }
func (d *bgTestDeps) TenantUserStore() core.TenantUserStore                 { return nil }
func (d *bgTestDeps) InvitationStore() core.InvitationStore                 { return nil }
func (d *bgTestDeps) InvitationSender() spi.InvitationSender                { return nil }
func (d *bgTestDeps) ConsentStore() core.ConsentStore                       { return nil }
func (d *bgTestDeps) MFAEnrollmentStore() core.MFAEnrollmentStore           { return nil }
func (d *bgTestDeps) PasswordCredentialStore() core.PasswordCredentialStore { return nil }
func (d *bgTestDeps) UserProvider() core.UserProvider                       { return nil }
func (d *bgTestDeps) AccountLockout() security.AccountLockout               { return nil }
func (d *bgTestDeps) DeviceSecretStore() core.DeviceSecretStore             { return nil }
func (d *bgTestDeps) PasswordResetStore() core.PasswordResetStore           { return nil }
func (d *bgTestDeps) EmailChangeStore() core.EmailChangeStore               { return nil }
func (d *bgTestDeps) InvalidateConnectionCache(string)                      {}

// newBGTestDeps wires the real memory stores break-glass needs.
func newBGTestDeps() *bgTestDeps {
	sink := audit.NewMemorySink(64)
	return &bgTestDeps{
		sessions:   memorystoreidentity.NewMemorySessionManager(time.Hour),
		breakGlass: memorystoreidentity.NewMemoryBreakGlassStore(),
		auditor:    audit.New(sink),
	}
}

// bgCtx builds a HandlerContext for a request stamped with actorID (as the
// admin middleware would after validating a bearer token), and optionally an
// :id path param (StdRouter would inject it in production).
func bgCtx(actorID, id, body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/break-glass", strings.NewReader(body))
	r.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	r = r.WithContext(withActor(r.Context(), actorID, ""))
	w := httptest.NewRecorder()
	return bgParamCtx{Context: core.NewContext(w, r), id: id}, w
}

// bgParamCtx layers a :id route param onto a core.Context — StdRouter would
// inject it via path matching in production; tests supply it directly.
type bgParamCtx struct {
	*core.Context
	id string
}

func (p bgParamCtx) Param(name string) string {
	if name == "id" {
		return p.id
	}
	return p.Context.Param(name)
}

func decodeSession(t *testing.T, w *httptest.ResponseRecorder) core.AdminSession {
	t.Helper()
	var a core.AdminSession
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	return a
}

func decodeErr(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode error response: %v (body=%s)", err, w.Body.String())
	}
	return m[core.KeyError]
}

func TestBreakGlassLifecycle_CreatePendingApproveActivates(t *testing.T) {
	d := newBGTestDeps()
	body := `{"target_user_id":"user-1","reason":"ticket-123","scope":"impersonate","require_approval":true}`
	ctx, w := bgCtx("admin-a", "", body)
	HandleCreateBreakGlass(d, ctx)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}
	created := decodeSession(t, w)
	if created.Status != core.AdminSessionPending {
		t.Fatalf("status = %q, want pending", created.Status)
	}
	if len(created.SessionIDs) != 0 {
		t.Fatalf("pending grant must not mint a session yet, got %v", created.SessionIDs)
	}

	// A DIFFERENT admin approves.
	actx, aw := bgCtx("admin-b", created.ID, "")
	HandleApproveBreakGlass(d, actx)
	if aw.Code != http.StatusOK {
		t.Fatalf("approve status = %d, body=%s", aw.Code, aw.Body.String())
	}
	approved := decodeSession(t, aw)
	if approved.Status != core.AdminSessionActive {
		t.Fatalf("status = %q, want active", approved.Status)
	}
	if approved.ApprovedBy != "admin-b" {
		t.Fatalf("approved_by = %q, want admin-b", approved.ApprovedBy)
	}
	if len(approved.SessionIDs) != 1 {
		t.Fatalf("impersonate scope must mint exactly one session, got %v", approved.SessionIDs)
	}
	sess, err := d.sessions.Get(context.Background(), approved.SessionIDs[0])
	if err != nil {
		t.Fatalf("minted session not found: %v", err)
	}
	if sess.UserID != "user-1" || sess.Kind != core.SessionKindAdminImpersonation {
		t.Fatalf("minted session = %+v, want UserID=user-1 Kind=%s", sess, core.SessionKindAdminImpersonation)
	}
}

func TestBreakGlassApprove_SelfApprovalRejected(t *testing.T) {
	d := newBGTestDeps()
	body := `{"target_user_id":"user-1","reason":"ticket-1","scope":"impersonate","require_approval":true}`
	ctx, w := bgCtx("admin-a", "", body)
	HandleCreateBreakGlass(d, ctx)
	created := decodeSession(t, w)

	actx, aw := bgCtx("admin-a", created.ID, "") // same actor as creator
	HandleApproveBreakGlass(d, actx)
	if aw.Code != http.StatusBadRequest {
		t.Fatalf("self-approve status = %d, want 400, body=%s", aw.Code, aw.Body.String())
	}
	if got := decodeErr(t, aw); got != core.ErrBreakGlassSelfApproval {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassSelfApproval)
	}

	// The grant must still be pending, and no session was left dangling.
	stored, err := d.breakGlass.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status != core.AdminSessionPending {
		t.Fatalf("status = %q after rejected self-approval, want pending", stored.Status)
	}
	all, _ := d.sessions.ListAll(context.Background())
	if len(all) != 0 {
		t.Fatalf("rejected approval must not leave a live session, got %d", len(all))
	}
}

func TestBreakGlassCreate_TTLCapEnforced(t *testing.T) {
	d := newBGTestDeps()
	body := `{"target_user_id":"user-1","reason":"ticket-1","ttl_seconds":7200}` // 2h > 1h cap
	ctx, w := bgCtx("admin-a", "", body)
	HandleCreateBreakGlass(d, ctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", w.Code, w.Body.String())
	}
	if got := decodeErr(t, w); got != core.ErrBreakGlassTTLExceeded {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassTTLExceeded)
	}
	list, _ := d.breakGlass.List(context.Background())
	if len(list) != 0 {
		t.Fatalf("a rejected create must not persist a record, got %d", len(list))
	}
}

func TestBreakGlassCreate_ReasonRequired(t *testing.T) {
	d := newBGTestDeps()
	ctx, w := bgCtx("admin-a", "", `{"target_user_id":"user-1"}`)
	HandleCreateBreakGlass(d, ctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if got := decodeErr(t, w); got != core.ErrBreakGlassReasonRequired {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassReasonRequired)
	}
}

func TestBreakGlassRevoke_CascadesSessionDestruction(t *testing.T) {
	d := newBGTestDeps()
	body := `{"target_user_id":"user-1","reason":"ticket-1","scope":"impersonate"}` // require_approval omitted -> activates immediately
	ctx, w := bgCtx("admin-a", "", body)
	HandleCreateBreakGlass(d, ctx)
	created := decodeSession(t, w)
	if created.Status != core.AdminSessionActive || len(created.SessionIDs) != 1 {
		t.Fatalf("created = %+v, want active with one session", created)
	}
	sid := created.SessionIDs[0]
	if _, err := d.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session should exist before revoke: %v", err)
	}

	rctx, rw := bgCtx("admin-a", created.ID, "")
	HandleRevokeBreakGlass(d, rctx)
	if rw.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body=%s", rw.Code, rw.Body.String())
	}
	if _, err := d.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("session must be destroyed by revoke cascade")
	}
	stored, err := d.breakGlass.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.Status != core.AdminSessionRevoked {
		t.Fatalf("status = %q, want revoked", stored.Status)
	}
}

func TestBreakGlassCreate_ReadonlyScopeNeverMintsSession(t *testing.T) {
	d := newBGTestDeps()
	body := `{"target_user_id":"user-1","reason":"ticket-1","scope":"readonly"}`
	ctx, w := bgCtx("admin-a", "", body)
	HandleCreateBreakGlass(d, ctx)
	created := decodeSession(t, w)
	if created.Status != core.AdminSessionActive {
		t.Fatalf("status = %q, want active (no approval required)", created.Status)
	}
	if len(created.SessionIDs) != 0 {
		t.Fatalf("readonly scope must never mint a session, got %v", created.SessionIDs)
	}
	all, _ := d.sessions.ListAll(context.Background())
	if len(all) != 0 {
		t.Fatalf("readonly grant must leave zero sessions — no bearer exists to mutate through, got %d", len(all))
	}
}

func TestSweepBreakGlassOnce_ExpiresAndCascades(t *testing.T) {
	d := newBGTestDeps()
	rctx := context.Background()
	sess, err := d.sessions.Create(rctx, "user-1")
	if err != nil {
		t.Fatalf("seed session: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	active := core.AdminSession{
		ID: "bg_active", AdminUserID: "admin-a", TargetUserID: "user-1",
		Reason: "ticket-1", Scope: core.AdminScopeImpersonate, Status: core.AdminSessionActive,
		CreatedAt: past.Add(-time.Hour), ExpiresAt: past, ApprovedBy: "admin-b", SessionIDs: []string{sess.ID},
	}
	pending := core.AdminSession{
		ID: "bg_pending", AdminUserID: "admin-a", TargetUserID: "user-2",
		Reason: "ticket-2", Scope: core.AdminScopeReadonly, Status: core.AdminSessionPending,
		CreatedAt: past.Add(-time.Hour), ExpiresAt: past,
	}
	if err := d.breakGlass.Create(rctx, active); err != nil {
		t.Fatalf("seed active: %v", err)
	}
	if err := d.breakGlass.Create(rctx, pending); err != nil {
		t.Fatalf("seed pending: %v", err)
	}

	n, err := SweepBreakGlassOnce(d, rctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("swept = %d, want 2", n)
	}
	if _, err := d.sessions.Get(rctx, sess.ID); err == nil {
		t.Fatalf("expiry sweep must destroy the derived session")
	}
	if _, err := d.breakGlass.Get(rctx, "bg_active"); err == nil {
		t.Fatalf("swept record should be gone from the store")
	}
}

func TestRecordBreakGlassEvent_CarriesEvidenceChainMetadata(t *testing.T) {
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)
	a := core.AdminSession{
		ID: "bg_1", AdminUserID: "admin-a", TargetUserID: "user-1", Reason: "ticket-42",
	}
	id := recordBreakGlassEvent(&bgTestDeps{auditor: rec}, context.Background(), "1.2.3.4", audit.EventAdminBreakGlassCreated, a)
	if id == "" {
		t.Fatal("expected a non-empty recorded event id")
	}
	evt, err := sink.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get recorded event: %v", err)
	}
	want := map[string]string{
		metaKeyAdminID:          "admin-a",
		metaKeyTargetUserID:     "user-1",
		metaKeyAdminSessionID:   "bg_1",
		metaKeyBreakGlassReason: "ticket-42",
	}
	for k, v := range want {
		if evt.Metadata[k] != v {
			t.Errorf("metadata[%q] = %q, want %q", k, evt.Metadata[k], v)
		}
	}
}
