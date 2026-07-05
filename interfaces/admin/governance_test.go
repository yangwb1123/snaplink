package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/admingovernance"
	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
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
func (d *gcTestDeps) ConnectionStore() connections.Store                       { return nil }
func (d *gcTestDeps) ConditionalAccessStore() conditionalaccess.Store          { return nil }
func (d *gcTestDeps) TenantUserStore() core.TenantUserStore                    { return nil }
func (d *gcTestDeps) InvitationStore() core.InvitationStore                    { return nil }
func (d *gcTestDeps) InvitationSender() spi.InvitationSender                   { return nil }
func (d *gcTestDeps) ConsentStore() core.ConsentStore                          { return nil }
func (d *gcTestDeps) MFAEnrollmentStore() core.MFAEnrollmentStore              { return nil }
func (d *gcTestDeps) PasswordCredentialStore() core.PasswordCredentialStore    { return nil }
func (d *gcTestDeps) UserProvider() core.UserProvider                          { return nil }
func (d *gcTestDeps) AccountLockout() security.AccountLockout                  { return nil }
func (d *gcTestDeps) DeviceSecretStore() core.DeviceSecretStore                { return nil }
func (d *gcTestDeps) PasswordResetStore() core.PasswordResetStore              { return nil }
func (d *gcTestDeps) EmailChangeStore() core.EmailChangeStore                  { return nil }
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
func (d *gcTestDeps) RevokeToken(context.Context, string) {}

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
