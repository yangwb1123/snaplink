package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreoauth"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/sessionhub"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// Token Portfolio handler tests exercise the REAL memory refresh-token store
// (memorystoreoauth.MemoryRefreshTokenStore implements SubjectIndex +
// ClientPurger + SubjectCounter) — no mocks. They prove the bulk-revoke
// reuses that store, is bounded by the storm caps, and threads the admin
// actor into the audit event.

// tpParamCtx layers a :subject route param onto a core.Context — StdRouter
// would inject it via path matching in production; tests supply it directly.
type tpParamCtx struct {
	*core.Context
	subject string
}

func (p tpParamCtx) Param(name string) string {
	if name == "subject" {
		return p.subject
	}
	return p.Context.Param(name)
}

// revokeCtx builds a POST bulk-revoke HandlerContext with a form body, stamped
// with actorID as the admin middleware would.
func revokeCtx(actorID, form string) (core.HandlerContext, *httptest.ResponseRecorder) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tokens/revoke", strings.NewReader(form))
	r.Header.Set(core.HeaderContentType, "application/x-www-form-urlencoded")
	r = r.WithContext(withActor(r.Context(), actorID, ""))
	w := httptest.NewRecorder()
	return core.NewContext(w, r), w
}

func seedTokens(t *testing.T, s *memorystoreoauth.MemoryRefreshTokenStore, subject, client string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		tok := fmt.Sprintf("%s-%s-%d", subject, client, i)
		if err := s.Issue(context.Background(), tok, &oauth.RefreshToken{
			UserID: subject, ClientID: client, FamilyID: "fam-" + tok,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed Issue: %v", err)
		}
	}
}

func decodeRevoke(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return out
}

// TestBulkRevoke_SubjectWithConfirm: a subject-scoped revoke with confirm=true
// deletes every refresh token the subject holds THROUGH the shared store, and
// the store reflects the deletion (proving reuse of the existing machinery).
func TestBulkRevoke_SubjectWithConfirm(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	seedTokens(t, s, "u1", "c1", 3)
	seedTokens(t, s, "u2", "c1", 2) // untouched subject

	ctx, w := revokeCtx("admin-1", "subject=u1&confirm=true")
	HandleBulkRevoke(s, nil, testLogger{}, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	if got := decodeRevoke(t, w)["revoked_count"]; got != float64(3) {
		t.Fatalf("revoked_count = %v, want 3", got)
	}
	// Store actually purged u1, left u2.
	if n, _ := s.CountForSubject(context.Background(), "u1", ""); n != 0 {
		t.Errorf("u1 still has %d tokens after revoke", n)
	}
	if n, _ := s.CountForSubject(context.Background(), "u2", ""); n != 2 {
		t.Errorf("u2 collateral damage: %d tokens left, want 2", n)
	}
}

// TestBulkRevoke_ConfirmationRequiredOverSoftCap: a batch past the soft cap
// without confirm is refused with bulk_revoke_confirmation_required and does
// NOT delete anything (storm protection).
func TestBulkRevoke_ConfirmationRequiredOverSoftCap(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	seedTokens(t, s, "u1", "c1", bulkRevokeSoftCap+1)

	ctx, w := revokeCtx("admin-1", "subject=u1") // no confirm
	HandleBulkRevoke(s, nil, testLogger{}, ctx)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if got := decodeRevoke(t, w)["error"]; got != core.ErrBulkRevokeConfirmationRequired {
		t.Fatalf("error = %v, want %s", got, core.ErrBulkRevokeConfirmationRequired)
	}
	if n, _ := s.CountForSubject(context.Background(), "u1", ""); n != bulkRevokeSoftCap+1 {
		t.Errorf("tokens were deleted despite the confirm gate: %d left", n)
	}
}

// TestBulkRevoke_BatchTooLarge: a batch past the hard cap is refused outright,
// even with confirm.
func TestBulkRevoke_BatchTooLarge(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	seedTokens(t, s, "u1", "c1", bulkRevokeHardCap+1)

	ctx, w := revokeCtx("admin-1", "subject=u1&confirm=true")
	HandleBulkRevoke(s, nil, testLogger{}, ctx)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
	if got := decodeRevoke(t, w)["error"]; got != core.ErrBulkRevokeBatchTooLarge {
		t.Fatalf("error = %v, want %s", got, core.ErrBulkRevokeBatchTooLarge)
	}
}

// TestBulkRevoke_ClientRequiresConfirm: a client-scoped revoke always needs
// confirm (it can't be cheaply pre-counted), then purges via the client purger.
func TestBulkRevoke_ClientRequiresConfirm(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	seedTokens(t, s, "u1", "c1", 2)
	seedTokens(t, s, "u2", "c1", 2)

	ctx, w := revokeCtx("admin-1", "client_id=c1") // no confirm
	HandleBulkRevoke(s, nil, testLogger{}, ctx)
	if w.Code != http.StatusConflict || decodeRevoke(t, w)["error"] != core.ErrBulkRevokeConfirmationRequired {
		t.Fatalf("client revoke without confirm: status=%d body=%s", w.Code, w.Body.String())
	}

	ctx2, w2 := revokeCtx("admin-1", "client_id=c1&confirm=true")
	HandleBulkRevoke(s, nil, testLogger{}, ctx2)
	if w2.Code != http.StatusOK || decodeRevoke(t, w2)["revoked_count"] != float64(4) {
		t.Fatalf("client revoke with confirm: status=%d body=%s", w2.Code, w2.Body.String())
	}
}

// TestBulkRevoke_EmptyScopeRejected: neither subject nor client is a 400 —
// never a wildcard-all.
func TestBulkRevoke_EmptyScopeRejected(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	ctx, w := revokeCtx("admin-1", "confirm=true")
	HandleBulkRevoke(s, nil, testLogger{}, ctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for empty scope", w.Code)
	}
}

// TestBulkRevoke_NilStore: no refresh store wired ⇒ 501, never a panic.
func TestBulkRevoke_NilStore(t *testing.T) {
	ctx, w := revokeCtx("admin-1", "subject=u1&confirm=true")
	HandleBulkRevoke(nil, nil, testLogger{}, ctx)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", w.Code)
	}
}

// TestBulkRevoke_AuditCarriesAdminActor: the governance audit event records the
// admin actor stamped by the middleware, plus the scope + count.
func TestBulkRevoke_AuditCarriesAdminActor(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	seedTokens(t, s, "u1", "c1", 2)
	sink := audit.NewMemorySink(16)
	auditor := audit.New(sink)

	ctx, w := revokeCtx("admin-42", "subject=u1&confirm=true")
	HandleBulkRevoke(s, auditor, testLogger{}, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	events, _ := sink.Query(context.Background(), audit.Query{})
	if len(events) != 1 {
		t.Fatalf("recorded %d audit events, want 1", len(events))
	}
	if events[0].ActorID != "admin-42" {
		t.Errorf("audit ActorID = %q, want admin-42", events[0].ActorID)
	}
}

// TestSubjectTokens_Count: the per-subject view returns the active
// refresh-token count via the store's counter.
func TestSubjectTokens_Count(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	seedTokens(t, s, "u1", "c1", 4)

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens/subjects/u1", nil)
	w := httptest.NewRecorder()
	ctx := tpParamCtx{Context: core.NewContext(w, r), subject: "u1"}
	HandleSubjectTokens(s, testLogger{}, ctx)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["counted"] != true || out["active_refresh_tokens"] != float64(4) {
		t.Fatalf("body = %v, want counted/4", out)
	}
}

// TestSubjectTokens_MissingSubject: an empty :subject is a 400.
func TestSubjectTokens_MissingSubject(t *testing.T) {
	s := memorystoreoauth.NewMemoryRefreshTokenStore()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens/subjects/", nil)
	w := httptest.NewRecorder()
	ctx := tpParamCtx{Context: core.NewContext(w, r), subject: ""}
	HandleSubjectTokens(s, testLogger{}, ctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// TestLinkedSessions_GroupsByGlobalSID exercises HandleLinkedSessions against
// a REAL sessionhub.Coordinator over a REAL MemoryLinkStore (no mocks, per
// AGENTS.md §0.5): a subject with TWO logins — one core-only, one that also
// fanned out into SAML — must come back as two groups, each carrying exactly
// its own legs, proving the flat ListBySubject rows are grouped by
// global_sid rather than flattened into one bucket.
func TestLinkedSessions_GroupsByGlobalSID(t *testing.T) {
	c := sessionhub.NewCoordinator(nil, nil, nil, nil)
	ctx := context.Background()

	gsid1 := sessionhub.NewGlobalSID()
	if err := c.Link(ctx, gsid1, sessionhub.ProtocolCore, "sess-1", "u1"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	gsid2 := sessionhub.NewGlobalSID()
	if err := c.Link(ctx, gsid2, sessionhub.ProtocolCore, "sess-2", "u1"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	if err := c.Link(ctx, gsid2, sessionhub.ProtocolSAML, "sess-2", "u1"); err != nil {
		t.Fatalf("Link: %v", err)
	}
	// A different subject's login must never appear in u1's result.
	gsidOther := sessionhub.NewGlobalSID()
	_ = c.Link(ctx, gsidOther, sessionhub.ProtocolCore, "sess-9", "someone-else")

	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sessions/linked/u1", nil)
	w := httptest.NewRecorder()
	hctx := tpParamCtx{Context: core.NewContext(w, r), subject: "u1"}
	HandleLinkedSessions(c, testLogger{}, hctx)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if out["subject"] != "u1" {
		t.Fatalf("subject = %v, want u1", out["subject"])
	}
	if out["total"] != float64(2) {
		t.Fatalf("total = %v, want 2 (two distinct global_sids)", out["total"])
	}
	groups, ok := out["linked_sessions"].([]any)
	if !ok || len(groups) != 2 {
		t.Fatalf("linked_sessions = %v, want 2 groups", out["linked_sessions"])
	}
	// Find the two-leg group (gsid2, core+SAML) and the one-leg group
	// (gsid1, core-only); every leg's Subject/ExternalRef must be u1's own
	// (LinkRecord carries no json tags, so field names serialize verbatim).
	var sawTwoLegGroup, sawOneLegGroup bool
	for _, g := range groups {
		group, _ := g.(map[string]any)
		legs, _ := group["legs"].([]any)
		for _, l := range legs {
			leg, _ := l.(map[string]any)
			if leg["Subject"] != "u1" {
				t.Fatalf("leaked a foreign leg into u1's groups: %+v", leg)
			}
		}
		switch len(legs) {
		case 2:
			sawTwoLegGroup = true
		case 1:
			sawOneLegGroup = true
		}
	}
	if !sawTwoLegGroup || !sawOneLegGroup {
		t.Fatalf("want one 1-leg group (gsid1) and one 2-leg group (gsid2), got: %+v", groups)
	}
}

// TestLinkedSessions_UnknownSubjectIsEmptyNotError: a subject with no
// recorded legs is NOT an error — governance reads never leak
// existence via a 404 (mirrors LinkStore.ListBySubject's own contract and
// HandleSubjectTokens' counted=false fallback).
func TestLinkedSessions_UnknownSubjectIsEmptyNotError(t *testing.T) {
	c := sessionhub.NewCoordinator(nil, nil, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sessions/linked/ghost", nil)
	w := httptest.NewRecorder()
	hctx := tpParamCtx{Context: core.NewContext(w, r), subject: "ghost"}
	HandleLinkedSessions(c, testLogger{}, hctx)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (unknown subject is not an error): %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	if out["total"] != float64(0) {
		t.Fatalf("total = %v, want 0", out["total"])
	}
	groups, ok := out["linked_sessions"].([]any)
	if !ok || len(groups) != 0 {
		t.Fatalf("linked_sessions = %v, want an empty array (not null)", out["linked_sessions"])
	}
}

// TestLinkedSessions_MissingSubject: an empty :subject is a 400, mirroring
// HandleSubjectTokens' own validation.
func TestLinkedSessions_MissingSubject(t *testing.T) {
	c := sessionhub.NewCoordinator(nil, nil, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/sessions/linked/", nil)
	w := httptest.NewRecorder()
	hctx := tpParamCtx{Context: core.NewContext(w, r), subject: ""}
	HandleLinkedSessions(c, testLogger{}, hctx)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// testLogger discards output.
type testLogger struct{}

func (testLogger) Info(string, ...any)  {}
func (testLogger) Error(string, ...any) {}
func (testLogger) Debug(string, ...any) {}
