package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/admingovernance"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// gcTestDeps is the minimal admin.Deps the generic change-approval workflow
// tests need. Every method the workflow doesn't touch returns its zero
// value, matching bgTestDeps's shape in break_glass_test.go. Uses the REAL
// admingovernance.MemoryApprovalStore (no mocks, per repo convention).
type gcTestDeps struct {
	store       admingovernance.ApprovalStore
	registry    *admingovernance.Registry
	actionTypes admingovernance.RequiredActionTypes
}

func (d *gcTestDeps) ApprovalStore() admingovernance.ApprovalStore             { return d.store }
func (d *gcTestDeps) ChangeRegistry() *admingovernance.Registry                { return d.registry }
func (d *gcTestDeps) ApprovalActionTypes() admingovernance.RequiredActionTypes { return d.actionTypes }
func (d *gcTestDeps) ProviderStore() provider.Store                            { return nil }
func (d *gcTestDeps) DeviceStore() device.Store                                { return nil }
func (d *gcTestDeps) LoginHistoryStore() device.HistoryStore                   { return nil }
func (d *gcTestDeps) ConnectionStore() connections.Store                       { return nil }
func (d *gcTestDeps) ClientStore() core.ClientStore                            { return nil }
func (d *gcTestDeps) SessionManager() core.SessionManager                      { return nil }
func (d *gcTestDeps) Permissions() permissions.Provider                        { return nil }
func (d *gcTestDeps) ConnectionProber() connections.Prober                     { return nil }
func (d *gcTestDeps) Metrics() *metrics.Metrics                                { return nil }
func (d *gcTestDeps) ConditionalAccessStore() conditionalaccess.Store          { return nil }
func (d *gcTestDeps) DomainResolver() connections.DNSResolver                  { return nil }
func (d *gcTestDeps) RecoveryCodeStore() core.RecoveryCodeStore                { return nil }
func (d *gcTestDeps) TenantUserStore() core.TenantUserStore                    { return nil }
func (d *gcTestDeps) InvitationStore() core.InvitationStore                    { return nil }
func (d *gcTestDeps) InvitationSender() spi.InvitationSender                   { return nil }
func (d *gcTestDeps) ConsentStore() core.ConsentStore                          { return nil }
func (d *gcTestDeps) MFAEnrollmentStore() core.MFAEnrollmentStore              { return nil }
func (d *gcTestDeps) PasswordCredentialStore() core.PasswordCredentialStore    { return nil }
func (d *gcTestDeps) PasswordHistoryStore() core.PasswordHistoryStore          { return nil }
func (d *gcTestDeps) UserProvider() core.UserProvider                          { return nil }
func (d *gcTestDeps) LifecycleStore() userlifecycle.Store                      { return nil }
func (d *gcTestDeps) AccountLockout() security.AccountLockout                  { return nil }
func (d *gcTestDeps) DeviceSecretStore() core.DeviceSecretStore                { return nil }
func (d *gcTestDeps) PasswordResetStore() core.PasswordResetStore              { return nil }
func (d *gcTestDeps) EmailChangeStore() core.EmailChangeStore                  { return nil }
func (d *gcTestDeps) RefreshTokenStore() oauth.RefreshTokenStore               { return nil }
func (d *gcTestDeps) InvalidateConnectionCache(string)                         {}
func (d *gcTestDeps) Auditor() *audit.Recorder                                 { return nil }
func (d *gcTestDeps) Logger() spi.Logger                                       { return bgTestLogger{} }
func (d *gcTestDeps) SessionMgr() core.SessionManager                          { return nil }
func (d *gcTestDeps) BreakGlassStore() core.BreakGlassStore                    { return nil }
func (d *gcTestDeps) MintImpersonationToken(context.Context, core.AdminSession) (core.ImpersonationCredential, error) {
	return core.ImpersonationCredential{}, errors.New("not implemented")
}
func (d *gcTestDeps) TargetHoldsAdminScope(context.Context, string, string) (bool, error) {
	return false, nil
}
func (d *gcTestDeps) RevokeToken(context.Context, string) error { return nil }

func newGCTestDeps() *gcTestDeps {
	return &gcTestDeps{store: admingovernance.NewMemoryApprovalStore()}
}

// gcParamCtx layers a :id route param onto a core.Context — StdRouter would
// inject it via path matching in production; tests supply it directly.
// Mirrors bgParamCtx in break_glass_test.go.
type gcParamCtx struct {
	*core.Context
	id string
}

func (p gcParamCtx) Param(name string) string {
	if name == "id" {
		return p.id
	}
	return p.Context.Param(name)
}

// gcCtx builds a HandlerContext for a request stamped with actorID (as the
// admin middleware would after validating a bearer token) and an :id param.
func gcCtx(method, path, actorID, id, body string) (core.HandlerContext, *httptest.ResponseRecorder) {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(withActor(r.Context(), actorID, ""))
	w := httptest.NewRecorder()
	return gcParamCtx{Context: core.NewContext(w, r), id: id}, w
}

func TestHandleAdminProposeChange_MissingReason(t *testing.T) {
	d := newGCTestDeps()
	ctx, rec := gcCtx(http.MethodPost, "/api/v1/admin/changes", "admin-a", "", `{"action_type":"tenant_delete"}`)
	HandleAdminProposeChange(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d; want 400 (missing reason)", rec.Code)
	}
}

func TestHandleAdminProposeChange_ActionTypeNotAllowed(t *testing.T) {
	d := newGCTestDeps()
	d.actionTypes = admingovernance.NewRequiredActionTypes([]string{"tenant_delete"})
	ctx, rec := gcCtx(http.MethodPost, "/api/v1/admin/changes", "admin-a", "",
		`{"action_type":"something_else","reason":"because"}`)
	HandleAdminProposeChange(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d; want 400 (action_type not allowed)", rec.Code)
	}
}

func TestChangeApprovalWorkflow_ProposeApproveLifecycle(t *testing.T) {
	d := newGCTestDeps()

	proposeCtx, proposeRec := gcCtx(http.MethodPost, "/api/v1/admin/changes", "admin-a", "",
		`{"action_type":"tenant_delete","reason":"customer offboarding","payload":{"id":"acme"}}`)
	HandleAdminProposeChange(d, proposeCtx)
	if proposeRec.Code != http.StatusCreated {
		t.Fatalf("propose code = %d; body=%s", proposeRec.Code, proposeRec.Body.String())
	}
	var created admingovernance.ChangeRequest
	if err := json.Unmarshal(proposeRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode propose response: %v", err)
	}
	if created.Status != admingovernance.ChangeStatusPending {
		t.Fatalf("Status = %q; want pending", created.Status)
	}
	var wire map[string]any
	if err := json.Unmarshal(proposeRec.Body.Bytes(), &wire); err != nil {
		t.Fatalf("decode propose wire response: %v", err)
	}
	if _, ok := wire["action_type"]; !ok {
		t.Fatalf("wire response lacks action_type: %s", proposeRec.Body.String())
	}
	payload, ok := wire["payload"].(map[string]any)
	if !ok || payload["id"] != "acme" {
		t.Fatalf("payload is not structured JSON: %#v", wire["payload"])
	}
	if _, legacy := wire["ActionType"]; legacy {
		t.Fatalf("wire response exposes Go field casing: %s", proposeRec.Body.String())
	}

	listCtx, listRec := gcCtx(http.MethodGet, "/api/v1/admin/changes", "admin-a", "", "")
	HandleAdminListChanges(d, listCtx)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list code = %d", listRec.Code)
	}

	getCtx, getRec := gcCtx(http.MethodGet, "/api/v1/admin/changes/"+created.ID, "admin-a", created.ID, "")
	HandleAdminGetChange(d, getCtx)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get code = %d", getRec.Code)
	}

	// Approve by a DIFFERENT admin.
	approveCtx, approveRec := gcCtx(http.MethodPost, "/api/v1/admin/changes/"+created.ID+"/approve", "admin-b", created.ID, "")
	HandleAdminApproveChange(d, approveCtx)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve code = %d; body=%s", approveRec.Code, approveRec.Body.String())
	}
	var approved admingovernance.ChangeRequest
	if err := json.Unmarshal(approveRec.Body.Bytes(), &approved); err != nil {
		t.Fatalf("decode approve response: %v", err)
	}
	if approved.Status != admingovernance.ChangeStatusApproved {
		t.Fatalf("Status after approve = %q; want approved (no applier registered)", approved.Status)
	}
	if approved.ApprovedBy != "admin-b" {
		t.Fatalf("ApprovedBy = %q; want admin-b", approved.ApprovedBy)
	}
}

func TestHandleAdminApproveChange_SelfApprovalRejected(t *testing.T) {
	d := newGCTestDeps()
	created, err := d.store.Propose(context.Background(), admingovernance.ChangeRequest{
		ID: "chg1", ActionType: "x", Reason: "r", ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	ctx, rec := gcCtx(http.MethodPost, "/api/v1/admin/changes/"+created.ID+"/approve", "admin-a", created.ID, "")
	HandleAdminApproveChange(d, ctx)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("self-approve code = %d; want 400", rec.Code)
	}
}

func TestHandleAdminApproveChange_InvokesRegisteredApplier(t *testing.T) {
	d := newGCTestDeps()
	d.registry = admingovernance.NewRegistry()
	applied := false
	d.registry.Register("tenant_delete", func(context.Context, []byte) error {
		applied = true
		return nil
	})
	created, err := d.store.Propose(context.Background(), admingovernance.ChangeRequest{
		ID: "chg1", ActionType: "tenant_delete", Reason: "r", ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	ctx, rec := gcCtx(http.MethodPost, "/api/v1/admin/changes/"+created.ID+"/approve", "admin-b", created.ID, "")
	HandleAdminApproveChange(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve code = %d; body=%s", rec.Code, rec.Body.String())
	}
	if !applied {
		t.Fatal("registered Applier was not invoked on approval")
	}
	var got admingovernance.ChangeRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != admingovernance.ChangeStatusApplied {
		t.Fatalf("Status = %q; want applied", got.Status)
	}
}

func TestHandleAdminApproveChange_FailedApplierMarksFailed(t *testing.T) {
	d := newGCTestDeps()
	d.registry = admingovernance.NewRegistry()
	d.registry.Register("boom", func(context.Context, []byte) error { return errors.New("downstream unavailable") })
	created, err := d.store.Propose(context.Background(), admingovernance.ChangeRequest{
		ID: "chg1", ActionType: "boom", Reason: "r", ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}

	ctx, rec := gcCtx(http.MethodPost, "/api/v1/admin/changes/"+created.ID+"/approve", "admin-b", created.ID, "")
	HandleAdminApproveChange(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve code = %d; body=%s", rec.Code, rec.Body.String())
	}
	var got admingovernance.ChangeRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != admingovernance.ChangeStatusFailed {
		t.Fatalf("Status = %q; want failed", got.Status)
	}
}

func TestHandleAdminRejectChange(t *testing.T) {
	d := newGCTestDeps()
	created, err := d.store.Propose(context.Background(), admingovernance.ChangeRequest{
		ID: "chg1", ActionType: "x", Reason: "r", ProposedBy: "admin-a",
	})
	if err != nil {
		t.Fatalf("Propose: %v", err)
	}
	ctx, rec := gcCtx(http.MethodPost, "/api/v1/admin/changes/"+created.ID+"/reject", "admin-b", created.ID, "")
	HandleAdminRejectChange(d, ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("reject code = %d", rec.Code)
	}
	var got admingovernance.ChangeRequest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Status != admingovernance.ChangeStatusRejected {
		t.Fatalf("Status = %q; want rejected", got.Status)
	}
}

func TestHandleAdminChangeRoutes_404WithoutStore(t *testing.T) {
	d := &gcTestDeps{} // no ApprovalStore wired
	ctx, rec := gcCtx(http.MethodGet, "/api/v1/admin/changes", "admin-a", "", "")
	HandleAdminListChanges(d, ctx)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d; want 404 when no ApprovalStore is wired", rec.Code)
	}
}

// TestMethodScopeForPath_SegmentBoundary guards against a bare-HasPrefix
// regression: a registered override for "/api/v1/admin/wasmauthz/check"
// must NOT match an unrelated future sibling route like
// "/api/v1/admin/wasmauthz/checkpoint" — only an exact path or a match
// followed by "/" counts.
func TestMethodScopeForPath_SegmentBoundary(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetMethodScope("/api/v1/admin/wasmauthz/check", ScopeRead)

	cases := []struct {
		path      string
		wantScope string
		wantOK    bool
	}{
		{"/api/v1/admin/wasmauthz/check", ScopeRead, true},
		{"/api/v1/admin/wasmauthz/check/", ScopeRead, true},
		{"/api/v1/admin/wasmauthz/check/extra", ScopeRead, true},
		{"/api/v1/admin/wasmauthz/checkpoint", "", false},
		{"/api/v1/admin/wasmauthz/check-and-apply", "", false},
	}
	for _, tc := range cases {
		scope, ok := mw.methodScopeForPath(tc.path)
		if ok != tc.wantOK || scope != tc.wantScope {
			t.Errorf("methodScopeForPath(%q) = (%q, %v); want (%q, %v)", tc.path, scope, ok, tc.wantScope, tc.wantOK)
		}
	}
}

type governanceDenialCase struct {
	name       string
	eventType  audit.EventType
	reason     string
	method     string
	path       string
	calls      int
	withTenant bool
	setup      func(*Middleware)
}

func runGovernanceRequest(mw *Middleware, method, path string) (int, http.Header, string) {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "198.51.100.7:4321"
	r.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	return w.Code, w.Header().Clone(), w.Body.String()
}

func TestHTTPGovernanceDenials_AuditExactlyOnceAndPreserveResponse(t *testing.T) {
	ipCfg, err := admingovernance.ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	cases := []governanceDenialCase{
		{name: "ip", eventType: audit.EventAdminIPDenied, reason: errAdminIPDenied,
			method: http.MethodGet, path: "/api/v1/admin/connections?token=not-recorded",
			setup: func(mw *Middleware) { mw.SetIPAllowlist(ipCfg, nil) }},
		{name: "rate", eventType: audit.EventAdminRateLimited, reason: errAdminRateLimitExceeded,
			method: http.MethodGet, path: "/api/v1/admin/connections", calls: 2,
			setup: func(mw *Middleware) { mw.SetRateLimit(1, 1) }},
		{name: "destructive", eventType: audit.EventAdminDestructiveConfirmRequired, reason: errDestructiveConfirmRequired,
			method: http.MethodDelete, path: "/api/v1/admin/tenants/acme?token=not-recorded",
			setup: func(mw *Middleware) {
				mw.SetDestructiveActions(admingovernance.NewDestructiveSet([]admingovernance.DestructiveRule{
					{Method: http.MethodDelete, PathPrefix: "/api/v1/admin/tenants/"},
				}))
			}},
		{name: "quota", eventType: audit.EventAdminWriteQuotaExceeded, reason: errAdminWriteQuotaExceeded,
			method: http.MethodPost, path: "/api/v1/admin/connections?token=not-recorded", calls: 2,
			withTenant: true,
			setup: func(mw *Middleware) {
				mw.SetWriteQuota(admingovernance.NewMemoryWriteQuotaStore(), 1, time.Hour, "tenant")
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newMW := func() *Middleware {
				mw := newTestMiddleware("admin-1")
				if tc.withTenant {
					mw.validator = fakeValidator{claims: &core.TokenClaims{Subject: "admin-1", Extra: map[string]string{core.KeyTenantID: "tenant-a"}}}
				}
				tc.setup(mw)
				return mw
			}
			calls := tc.calls
			if calls == 0 {
				calls = 1
			}
			base := newMW()
			var baseStatus int
			var baseHeaders http.Header
			var baseBody string
			for i := 0; i < calls; i++ {
				baseStatus, baseHeaders, baseBody = runGovernanceRequest(base, tc.method, tc.path)
			}
			sink := audit.NewMemorySink(8)
			wired := newMW()
			wired.SetAuditRecorder(audit.New(sink))
			var gotStatus int
			var gotHeaders http.Header
			var gotBody string
			for i := 0; i < calls; i++ {
				gotStatus, gotHeaders, gotBody = runGovernanceRequest(wired, tc.method, tc.path)
			}
			if gotStatus != baseStatus || gotBody != baseBody || !reflect.DeepEqual(gotHeaders, baseHeaders) {
				t.Fatalf("wired response differs: got (%d, %q, %#v), base (%d, %q, %#v)", gotStatus, gotBody, gotHeaders, baseStatus, baseBody, baseHeaders)
			}
			events, err := sink.Query(context.Background(), audit.Query{Type: tc.eventType})
			if err != nil {
				t.Fatalf("query denial event: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("denial events = %d; want exactly 1", len(events))
			}
			e := events[0]
			if e.Outcome != audit.OutcomeFailure || e.ActorIP != "198.51.100.7" {
				t.Fatalf("event outcome/ip = %q/%q; want failure/198.51.100.7", e.Outcome, e.ActorIP)
			}
			wantMeta := map[string]string{"method": tc.method, "path": stringsBeforeQuery(tc.path), "reason": tc.reason}
			if !reflect.DeepEqual(e.Metadata, wantMeta) {
				t.Fatalf("metadata = %#v; want %#v", e.Metadata, wantMeta)
			}
			if tc.withTenant {
				if e.ActorID != "admin-1" || e.TenantID != "tenant-a" {
					t.Fatalf("quota actor evidence = (%q, %q); want (admin-1, tenant-a)", e.ActorID, e.TenantID)
				}
			} else if e.ActorID != "" || e.TenantID != "" {
				t.Fatalf("unexpected actor evidence = (%q, %q)", e.ActorID, e.TenantID)
			}
			if e.Reason != "" || e.TokenID != "" {
				t.Fatalf("sensitive/unscoped event fields populated: reason=%q token_id=%q", e.Reason, e.TokenID)
			}
		})
	}
}

func stringsBeforeQuery(path string) string {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

type failingDenialSink struct{}

func (failingDenialSink) Record(context.Context, *audit.Event) error {
	return errors.New("audit sink unavailable")
}
func (failingDenialSink) Query(context.Context, audit.Query) ([]*audit.Event, error) { return nil, nil }
func (failingDenialSink) Get(context.Context, string) (*audit.Event, error)          { return nil, nil }

func TestHTTPGovernanceDenials_HEADResponseIsUnchanged(t *testing.T) {
	ipCfg, err := admingovernance.ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	cases := []struct {
		name  string
		setup func(*Middleware)
		path  string
	}{
		{"ip", func(m *Middleware) { m.SetIPAllowlist(ipCfg, nil) }, "/api/v1/admin/x"},
		{"rate", func(m *Middleware) { m.SetRateLimit(1, 1) }, "/api/v1/admin/x"},
		{"confirm", func(m *Middleware) {
			m.SetDestructiveActions(admingovernance.NewDestructiveSet([]admingovernance.DestructiveRule{{Method: http.MethodHead, PathPrefix: "/api/v1/admin/x"}}))
		}, "/api/v1/admin/x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := newTestMiddleware("admin-1")
			tc.setup(base)
			baseStatus, baseHeaders, baseBody := runGovernanceRequest(base, http.MethodHead, tc.path)
			sink := audit.NewMemorySink(4)
			wired := newTestMiddleware("admin-1")
			tc.setup(wired)
			wired.SetAuditRecorder(audit.New(sink))
			gotStatus, gotHeaders, gotBody := runGovernanceRequest(wired, http.MethodHead, tc.path)
			if gotStatus != baseStatus || gotBody != baseBody || !reflect.DeepEqual(gotHeaders, baseHeaders) {
				t.Fatalf("wired HEAD response differs: got (%d, %q, %#v), base (%d, %q, %#v)", gotStatus, gotBody, gotHeaders, baseStatus, baseBody, baseHeaders)
			}
		})
	}
}

func TestHTTPGovernanceDenials_NilAndFailingRecorderAreFailOpen(t *testing.T) {
	ipCfg, err := admingovernance.ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	cases := []struct {
		name   string
		method string
		path   string
		calls  int
		setup  func(*Middleware)
		status int
	}{
		{"ip", http.MethodGet, "/api/v1/admin/x", 1, func(m *Middleware) { m.SetIPAllowlist(ipCfg, nil) }, http.StatusForbidden},
		{"rate", http.MethodGet, "/api/v1/admin/x", 2, func(m *Middleware) { m.SetRateLimit(1, 1) }, http.StatusTooManyRequests},
		{"confirm", http.MethodDelete, "/api/v1/admin/tenants/acme", 1, func(m *Middleware) {
			m.SetDestructiveActions(admingovernance.NewDestructiveSet([]admingovernance.DestructiveRule{{Method: http.MethodDelete, PathPrefix: "/api/v1/admin/tenants/"}}))
		}, http.StatusConflict},
		{"quota", http.MethodPost, "/api/v1/admin/x", 2, func(m *Middleware) { m.SetWriteQuota(admingovernance.NewMemoryWriteQuotaStore(), 1, time.Hour, "") }, http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, rec := range []*audit.Recorder{nil, audit.New(failingDenialSink{})} {
				mw := newTestMiddleware("admin-1")
				tc.setup(mw)
				mw.SetAuditRecorder(rec)
				var status int
				for i := 0; i < tc.calls; i++ {
					status, _, _ = runGovernanceRequest(mw, tc.method, tc.path)
				}
				if status != tc.status {
					t.Fatalf("status with recorder %v = %d; want %d", rec != nil, status, tc.status)
				}
			}
		})
	}
}
