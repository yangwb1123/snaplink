package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/defaulttoken"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/admingovernance"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
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
	sink       *audit.MemorySink
	// tokens is a REAL revocable opaque-token issuer (no mock): break-glass
	// impersonation mints its bearer through it and the cascade revokes it, so
	// the handler's revoke-invalidates path is exercised end to end.
	tokens *defaulttoken.SessionTokenIssuer
	// privilegedTargets are user ids the privilege floor must treat as admins
	// (TargetHoldsAdminScope). Empty ⇒ no target is privileged, so the floor is a
	// no-op and every pre-existing break-glass test behaves unchanged.
	privilegedTargets map[string]bool
}

func (d *bgTestDeps) SessionMgr() core.SessionManager                       { return d.sessions }
func (d *bgTestDeps) ClientStore() core.ClientStore                         { return nil }
func (d *bgTestDeps) SessionManager() core.SessionManager                   { return d.sessions }
func (d *bgTestDeps) Permissions() permissions.Provider                     { return nil }
func (d *bgTestDeps) ConnectionProber() connections.Prober                  { return nil }
func (d *bgTestDeps) Metrics() *metrics.Metrics                             { return nil }
func (d *bgTestDeps) BreakGlassStore() core.BreakGlassStore                 { return d.breakGlass }
func (d *bgTestDeps) Auditor() *audit.Recorder                              { return d.auditor }
func (d *bgTestDeps) Logger() spi.Logger                                    { return bgTestLogger{} }
func (d *bgTestDeps) ProviderStore() provider.Store                         { return nil }
func (d *bgTestDeps) DeviceStore() device.Store                             { return nil }
func (d *bgTestDeps) LoginHistoryStore() device.HistoryStore                { return nil }
func (d *bgTestDeps) ConnectionStore() connections.Store                    { return nil }
func (d *bgTestDeps) ConditionalAccessStore() conditionalaccess.Store       { return nil }
func (d *bgTestDeps) DomainResolver() connections.DNSResolver               { return nil }
func (d *bgTestDeps) TenantUserStore() core.TenantUserStore                 { return nil }
func (d *bgTestDeps) InvitationStore() core.InvitationStore                 { return nil }
func (d *bgTestDeps) InvitationSender() spi.InvitationSender                { return nil }
func (d *bgTestDeps) RecoveryCodeStore() core.RecoveryCodeStore             { return nil }
func (d *bgTestDeps) ConsentStore() core.ConsentStore                       { return nil }
func (d *bgTestDeps) MFAEnrollmentStore() core.MFAEnrollmentStore           { return nil }
func (d *bgTestDeps) PasswordCredentialStore() core.PasswordCredentialStore { return nil }
func (d *bgTestDeps) PasswordHistoryStore() core.PasswordHistoryStore       { return nil }
func (d *bgTestDeps) UserProvider() core.UserProvider                       { return nil }
func (d *bgTestDeps) LifecycleStore() userlifecycle.Store                   { return nil }
func (d *bgTestDeps) AccountLockout() security.AccountLockout               { return nil }
func (d *bgTestDeps) DeviceSecretStore() core.DeviceSecretStore             { return nil }
func (d *bgTestDeps) PasswordResetStore() core.PasswordResetStore           { return nil }
func (d *bgTestDeps) EmailChangeStore() core.EmailChangeStore               { return nil }
func (d *bgTestDeps) RefreshTokenStore() oauth.RefreshTokenStore            { return nil }
func (d *bgTestDeps) InvalidateConnectionCache(string)                      {}
func (d *bgTestDeps) ApprovalStore() admingovernance.ApprovalStore          { return nil }
func (d *bgTestDeps) ChangeRegistry() *admingovernance.Registry             { return nil }
func (d *bgTestDeps) ApprovalActionTypes() admingovernance.RequiredActionTypes {
	return nil
}

// MintImpersonationToken mirrors *sso.Server's real mint but through the test's
// own real SessionTokenIssuer: sub=target, act=admin, break_glass_admin_session_id
// in Extra, no scope. It refuses any non-impersonate/escalate scope structurally.
func (d *bgTestDeps) MintImpersonationToken(ctx context.Context, a core.AdminSession) (core.ImpersonationCredential, error) {
	if a.Scope != core.AdminScopeImpersonate && a.Scope != core.AdminScopeEscalate {
		return core.ImpersonationCredential{}, errors.New("scope may not impersonate")
	}
	sid := ""
	if len(a.SessionIDs) > 0 {
		sid = a.SessionIDs[0]
	}
	tok, err := d.tokens.Issue(ctx, &core.Subject{
		ID:       a.TargetUserID,
		ClientID: core.BreakGlassImpersonationClientID,
		SID:      sid,
		Actor:    &core.ActorClaim{Subject: a.AdminUserID},
		Claims: map[string]string{
			core.ClaimBreakGlassAdminSessionID: a.ID,
			core.ClaimBreakGlass:               "true",
		},
	}, nil)
	if err != nil {
		return core.ImpersonationCredential{}, err
	}
	return core.ImpersonationCredential{Token: tok.AccessToken, TokenType: tok.TokenType, ExpiresIn: tok.ExpiresIn, SessionID: sid}, nil
}

func (d *bgTestDeps) RevokeToken(ctx context.Context, token string) { _ = d.tokens.Revoke(ctx, token) }

// TargetHoldsAdminScope mirrors *sso.Server's real floor: a configured set of
// privileged targets stands in for the permissions.Provider admin-scope lookup.
func (d *bgTestDeps) TargetHoldsAdminScope(_ context.Context, targetUserID, _ string) (bool, error) {
	return d.privilegedTargets[targetUserID], nil
}

// newBGTestDeps wires the real memory stores break-glass needs.
func newBGTestDeps() *bgTestDeps {
	sink := audit.NewMemorySink(64)
	return &bgTestDeps{
		sessions:   memorystoreidentity.NewMemorySessionManager(time.Hour),
		breakGlass: memorystoreidentity.NewMemoryBreakGlassStore(),
		auditor:    audit.New(sink),
		sink:       sink,
		tokens:     defaulttoken.NewSessionTokenIssuer(),
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

// panicSessionManagerBG wraps a real SessionManager but panics on Destroy for
// one specific sessionID, simulating a buggy operator-supplied SessionManager
// implementation invoked from the break-glass sweep's revoke cascade.
type panicSessionManagerBG struct {
	core.SessionManager
	panicOn string
}

func (p *panicSessionManagerBG) Destroy(ctx context.Context, sessionID string) error {
	if sessionID == p.panicOn {
		panic("boom: simulated SessionManager bug")
	}
	return p.SessionManager.Destroy(ctx, sessionID)
}

// TestSweepBreakGlassOnce_PanicInCascadeRecovered locks the panic-containment
// this sweep must provide: SweepBreakGlassOnce is driven by
// sso.Server.RunBreakGlassSweeper's PERMANENT background goroutine (no
// recover of its own, by design), so a panic anywhere in the pluggable
// SessionManager/TokenIssuer/Auditor calls it fans out to must be contained
// per-grant, not escape and crash the whole process. Without the recover()
// in sweepExpiredGrantSafe, this test itself would panic and crash the test
// binary — the same blast radius the real sweeper goroutine would have.
func TestSweepBreakGlassOnce_PanicInCascadeRecovered(t *testing.T) {
	d := newBGTestDeps()
	rctx := context.Background()

	sess1, err := d.sessions.Create(rctx, "user-1")
	if err != nil {
		t.Fatalf("seed session 1: %v", err)
	}
	sess2, err := d.sessions.Create(rctx, "user-2")
	if err != nil {
		t.Fatalf("seed session 2: %v", err)
	}
	// A buggy SessionManager that panics destroying sess1's session only.
	d.sessions = &panicSessionManagerBG{SessionManager: d.sessions, panicOn: sess1.ID}

	past := time.Now().Add(-time.Minute)
	bad := core.AdminSession{
		ID: "bg_bad", AdminUserID: "admin-a", TargetUserID: "user-1",
		Reason: "ticket-1", Scope: core.AdminScopeImpersonate, Status: core.AdminSessionActive,
		CreatedAt: past.Add(-time.Hour), ExpiresAt: past, ApprovedBy: "admin-b", SessionIDs: []string{sess1.ID},
	}
	good := core.AdminSession{
		ID: "bg_good", AdminUserID: "admin-a", TargetUserID: "user-2",
		Reason: "ticket-2", Scope: core.AdminScopeImpersonate, Status: core.AdminSessionActive,
		CreatedAt: past.Add(-time.Hour), ExpiresAt: past, ApprovedBy: "admin-b", SessionIDs: []string{sess2.ID},
	}
	if err := d.breakGlass.Create(rctx, bad); err != nil {
		t.Fatalf("seed bad: %v", err)
	}
	if err := d.breakGlass.Create(rctx, good); err != nil {
		t.Fatalf("seed good: %v", err)
	}

	// The call itself must not panic (and thus must not crash the process).
	n, err := SweepBreakGlassOnce(d, rctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n != 2 {
		t.Fatalf("swept = %d, want 2", n)
	}

	// Fault isolation: the SECOND (unrelated) grant's cascade must still have
	// run despite the first one panicking.
	if _, err := d.sessions.Get(rctx, sess2.ID); err == nil {
		t.Fatalf("good grant's session must still be destroyed by the sweep")
	}
	evts, _ := d.sink.Query(rctx, audit.Query{})
	var sawGood bool
	for _, e := range evts {
		if e.Type == audit.EventAdminBreakGlassExpired && e.Metadata[metaKeyAdminSessionID] == "bg_good" {
			sawGood = true
		}
	}
	if !sawGood {
		t.Fatalf("expiry audit event for the good grant must still be recorded")
	}
}

// bgCreateActiveImpersonate creates an immediately-active impersonate grant
// (require_approval omitted) and returns its id.
func bgCreateActiveImpersonate(t *testing.T, d *bgTestDeps, admin, target string) string {
	t.Helper()
	body := `{"target_user_id":"` + target + `","reason":"ticket-1","scope":"impersonate"}`
	ctx, w := bgCtx(admin, "", body)
	HandleCreateBreakGlass(d, ctx)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", w.Code, w.Body.String())
	}
	return decodeSession(t, w).ID
}

func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, w.Body.String())
	}
	return m
}

func TestBreakGlassImpersonate_ReadonlyStructurallyRejected(t *testing.T) {
	d := newBGTestDeps()
	ctx, w := bgCtx("admin-a", "", `{"target_user_id":"user-1","reason":"t1","scope":"readonly"}`)
	HandleCreateBreakGlass(d, ctx)
	id := decodeSession(t, w).ID

	ictx, iw := bgCtx("admin-a", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusForbidden {
		t.Fatalf("readonly impersonate status = %d, want 403, body=%s", iw.Code, iw.Body.String())
	}
	if got := decodeErr(t, iw); got != core.ErrBreakGlassNotImpersonable {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassNotImpersonable)
	}
	stored, _ := d.breakGlass.Get(context.Background(), id)
	if len(stored.ImpersonationTokens) != 0 {
		t.Fatalf("readonly grant must never register a token, got %v", stored.ImpersonationTokens)
	}
}

func TestBreakGlassImpersonate_PendingRejected(t *testing.T) {
	d := newBGTestDeps()
	ctx, w := bgCtx("admin-a", "", `{"target_user_id":"user-1","reason":"t1","scope":"impersonate","require_approval":true}`)
	HandleCreateBreakGlass(d, ctx)
	id := decodeSession(t, w).ID // still pending — no second approval yet

	ictx, iw := bgCtx("admin-a", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusConflict {
		t.Fatalf("pending impersonate status = %d, want 409, body=%s", iw.Code, iw.Body.String())
	}
	if got := decodeErr(t, iw); got != core.ErrBreakGlassNotActive {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassNotActive)
	}
}

func TestBreakGlassImpersonate_NonOwnerRejected(t *testing.T) {
	d := newBGTestDeps()
	id := bgCreateActiveImpersonate(t, d, "admin-a", "user-1")

	// A DIFFERENT admin (admin-b) must not be able to act under admin-a's grant.
	ictx, iw := bgCtx("admin-b", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusForbidden {
		t.Fatalf("non-owner impersonate status = %d, want 403, body=%s", iw.Code, iw.Body.String())
	}
	if got := decodeErr(t, iw); got != core.ErrBreakGlassNotOwner {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassNotOwner)
	}
}

func TestBreakGlassImpersonate_RevokedGrantRejected(t *testing.T) {
	d := newBGTestDeps()
	id := bgCreateActiveImpersonate(t, d, "admin-a", "user-1")
	rctx, _ := bgCtx("admin-a", id, "")
	HandleRevokeBreakGlass(d, rctx)

	ictx, iw := bgCtx("admin-a", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusConflict {
		t.Fatalf("revoked impersonate status = %d, want 409, body=%s", iw.Code, iw.Body.String())
	}
	if got := decodeErr(t, iw); got != core.ErrBreakGlassNotActive {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassNotActive)
	}
}

func TestBreakGlassImpersonate_PrivilegedTargetRefused(t *testing.T) {
	d := newBGTestDeps()
	id := bgCreateActiveImpersonate(t, d, "admin-a", "user-1")

	// The target becomes privileged AFTER the grant was created (TOCTOU): the
	// live-bearer mint MUST re-check the floor and refuse.
	d.privilegedTargets = map[string]bool{"user-1": true}

	ictx, iw := bgCtx("admin-a", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusForbidden {
		t.Fatalf("privileged-target impersonate = %d, want 403, body=%s", iw.Code, iw.Body.String())
	}
	if got := decodeErr(t, iw); got != core.ErrBreakGlassTargetPrivileged {
		t.Fatalf("error = %q, want %q", got, core.ErrBreakGlassTargetPrivileged)
	}
	// The error path is still a credential endpoint — no-store on EVERY response.
	if iw.Header().Get("Cache-Control") != "no-store" || iw.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("403 error response must carry no-store/no-cache, got %q/%q",
			iw.Header().Get("Cache-Control"), iw.Header().Get("Pragma"))
	}
	// No bearer was minted or registered under the grant.
	stored, _ := d.breakGlass.Get(context.Background(), id)
	if len(stored.ImpersonationTokens) != 0 {
		t.Fatalf("a refused privileged-target mint must register no token, got %v", stored.ImpersonationTokens)
	}
}

func TestBreakGlassImpersonate_ActiveMintsMarkedTargetTokenAndRevokeInvalidates(t *testing.T) {
	d := newBGTestDeps()
	rctx := context.Background()
	id := bgCreateActiveImpersonate(t, d, "admin-a", "user-1")

	ictx, iw := bgCtx("admin-a", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusOK {
		t.Fatalf("impersonate status = %d, want 200, body=%s", iw.Code, iw.Body.String())
	}
	if iw.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("credential response must be no-store, got %q", iw.Header().Get("Cache-Control"))
	}
	resp := decodeMap(t, iw)
	token, _ := resp[core.KeyAccessToken].(string)
	if token == "" {
		t.Fatalf("no access_token in impersonate response: %v", resp)
	}
	if resp[respKeyKind] != core.SessionKindAdminImpersonation {
		t.Fatalf("kind = %v, want %s", resp[respKeyKind], core.SessionKindAdminImpersonation)
	}

	// NON-BYPASS: the minted token authenticates as the TARGET user, and it
	// carries the evidence chain (which grant it acts under).
	claims, err := d.tokens.Validate(rctx, token)
	if err != nil {
		t.Fatalf("minted token must validate: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("token sub = %q, want target user-1 (never the admin)", claims.Subject)
	}
	if claims.Extra[core.ClaimBreakGlassAdminSessionID] != id {
		t.Fatalf("token missing break-glass grant id in claims: %v", claims.Extra)
	}

	// The token is registered under the grant for the cascade.
	stored, _ := d.breakGlass.Get(rctx, id)
	if len(stored.ImpersonationTokens) != 1 || stored.ImpersonationTokens[0] != token {
		t.Fatalf("token not registered under grant: %v", stored.ImpersonationTokens)
	}

	// Revoking the grant invalidates the impersonation credential immediately.
	rc, _ := bgCtx("admin-a", id, "")
	HandleRevokeBreakGlass(d, rc)
	if _, err := d.tokens.Validate(rctx, token); err == nil {
		t.Fatalf("revoking the grant MUST invalidate the impersonation token")
	}
}

func TestBreakGlassImpersonate_ExpirySweepRevokesToken(t *testing.T) {
	d := newBGTestDeps()
	rctx := context.Background()
	// A token minted under a now-expired active grant.
	tok, err := d.tokens.Issue(rctx, &core.Subject{ID: "user-1"}, nil)
	if err != nil {
		t.Fatalf("seed token: %v", err)
	}
	past := time.Now().Add(-time.Minute)
	a := core.AdminSession{
		ID: "bg_exp", AdminUserID: "admin-a", TargetUserID: "user-1", Reason: "t1",
		Scope: core.AdminScopeImpersonate, Status: core.AdminSessionActive,
		CreatedAt: past.Add(-time.Hour), ExpiresAt: past, ApprovedBy: "admin-b",
		ImpersonationTokens: []string{tok.AccessToken},
	}
	if err := d.breakGlass.Create(rctx, a); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	if _, err := d.tokens.Validate(rctx, tok.AccessToken); err != nil {
		t.Fatalf("token should be valid before sweep: %v", err)
	}
	if _, err := SweepBreakGlassOnce(d, rctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if _, err := d.tokens.Validate(rctx, tok.AccessToken); err == nil {
		t.Fatalf("expiry sweep MUST revoke the impersonation token")
	}
}

func TestBreakGlassImpersonate_StartedAuditCarriesEvidenceChain(t *testing.T) {
	d := newBGTestDeps()
	id := bgCreateActiveImpersonate(t, d, "admin-a", "user-1")
	ictx, iw := bgCtx("admin-a", id, "")
	HandleImpersonateBreakGlass(d, ictx)
	if iw.Code != http.StatusOK {
		t.Fatalf("impersonate status = %d, body=%s", iw.Code, iw.Body.String())
	}
	evts, err := d.sink.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	var found *audit.Event
	for _, e := range evts {
		if e.Type == audit.EventAdminBreakGlassImpersonationStarted {
			found = e
		}
	}
	if found == nil {
		t.Fatal("no admin_break_glass_impersonation_started event recorded")
	}
	want := map[string]string{
		metaKeyAdminID:        "admin-a",
		metaKeyTargetUserID:   "user-1",
		metaKeyAdminSessionID: id,
	}
	for k, v := range want {
		if found.Metadata[k] != v {
			t.Errorf("started event metadata[%q] = %q, want %q", k, found.Metadata[k], v)
		}
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
