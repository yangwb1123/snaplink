package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/tenant"
	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

// Delegated org-admin surface (w2.11): /me/organizations/:tenant_id/{members,
// invitations}. A TenantRoleAdmin of tenant X manages ONLY tenant X's roster +
// invitations via the subject bearer, WITHOUT the platform-wide admin scope.

const (
	orgClientID = "oa-app"
	orgTenant   = "acme"
	orgOther    = "globex"
)

type orgH struct {
	url     string
	issuer  sso.TokenIssuer
	members core.TenantUserStore
	invites core.InvitationStore
	sink    *audit.MemorySink
}

// newOrgHarness wires a server with the real Memory tenant-user + invitation
// stores (no mocks) plus an in-memory audit sink. extra options let a test add
// an invitation sender or the tenant store + suspension gate.
func newOrgHarness(t *testing.T, extra ...sso.Option) *orgH {
	t.Helper()
	ctx := context.Background()
	users := defaultimpl.NewMemoryUserProvider()
	for _, u := range []string{"u-admin", "u-admin2", "u-member", "u-other"} {
		_ = users.CreateOrUpdate(ctx, &sso.User{ID: u})
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: orgClientID, Secret: "s", Active: true, TokenStrategy: "jwt"})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	members := defaultimpl.NewMemoryTenantUserStore()
	invites := defaultimpl.NewMemoryInvitationStore()
	sink := audit.NewMemorySink(64)
	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantUserStore(members),
		sso.WithInvitationStore(invites),
		sso.WithAuditRecorder(audit.New(sink)),
	}
	opts = append(opts, extra...)
	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return &orgH{url: hs.URL, issuer: issuer, members: members, invites: invites, sink: sink}
}

func (h *orgH) seed(t *testing.T, tenantID, userID string, role core.TenantRole) {
	t.Helper()
	if err := h.members.Add(context.Background(), &core.TenantMembership{
		TenantID: tenantID, UserID: userID, Role: role, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed membership %s/%s: %v", tenantID, userID, err)
	}
}

func (h *orgH) token(t *testing.T, userID string) string {
	t.Helper()
	tok, err := h.issuer.Issue(context.Background(), &sso.Subject{ID: userID, ClientID: orgClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("issue token for %s: %v", userID, err)
	}
	return tok.AccessToken
}

// do performs a request and returns status + the RAW response body (bytes are
// what the byte-identical anti-enumeration assertions compare).
func (h *orgH) do(t *testing.T, method, path, bearer string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, h.url+path, r)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestOrgAdmin_ListMembers_AdminAllowed(t *testing.T) {
	h := newOrgHarness(t)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	h.seed(t, orgTenant, "u-member", core.TenantRoleMember)

	code, body := h.do(t, http.MethodGet, "/me/organizations/acme/members", h.token(t, "u-admin"), nil)
	if code != http.StatusOK {
		t.Fatalf("list members status=%d body=%s, want 200", code, body)
	}
	var out struct {
		Members []struct {
			UserID string `json:"user_id"`
			Role   string `json:"role"`
		} `json:"members"`
	}
	_ = json.Unmarshal(body, &out)
	if len(out.Members) != 2 {
		t.Fatalf("roster size=%d, want 2 (%s)", len(out.Members), body)
	}
}

// The three authorization-failure cases (tenant-absent, not-a-member,
// member-but-not-admin) AND a cross-tenant admin attempt MUST all collapse to
// one byte-identical 403 forbidden — no branch reveals which condition failed.
func TestOrgAdmin_Forbidden_ByteIdenticalCollapse(t *testing.T) {
	h := newOrgHarness(t)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	h.seed(t, orgTenant, "u-member", core.TenantRoleMember)
	h.seed(t, orgOther, "u-other", core.TenantRoleAdmin) // admin of a DIFFERENT tenant

	// member-but-not-admin of acme
	cA, bA := h.do(t, http.MethodGet, "/me/organizations/acme/members", h.token(t, "u-member"), nil)
	// not-a-member of acme
	cB, bB := h.do(t, http.MethodGet, "/me/organizations/acme/members", h.token(t, "u-other"), nil)
	// tenant-absent (no such org)
	cC, bC := h.do(t, http.MethodGet, "/me/organizations/nosuchorg/members", h.token(t, "u-member"), nil)
	// cross-tenant: admin of globex reaching into acme
	cD, bD := h.do(t, http.MethodGet, "/me/organizations/acme/members", h.token(t, "u-other"), nil)

	for i, c := range []int{cA, cB, cC, cD} {
		if c != http.StatusForbidden {
			t.Fatalf("case %d status=%d, want 403", i, c)
		}
	}
	if !bytes.Equal(bA, bB) || !bytes.Equal(bB, bC) || !bytes.Equal(bC, bD) {
		t.Fatalf("403 bodies not byte-identical: %q %q %q %q", bA, bB, bC, bD)
	}
	if !bytes.Contains(bA, []byte(`"forbidden"`)) {
		t.Fatalf("403 body missing forbidden code: %s", bA)
	}
}

func TestOrgAdmin_NonAdminMemberBlocked_AllVerbs(t *testing.T) {
	h := newOrgHarness(t, sso.WithInvitationSender(&captureInviteSender{}))
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	h.seed(t, orgTenant, "u-member", core.TenantRoleMember)
	tok := h.token(t, "u-member")

	cases := []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/me/organizations/acme/members", nil},
		{http.MethodPut, "/me/organizations/acme/members/u-admin", map[string]any{"role": "member"}},
		{http.MethodDelete, "/me/organizations/acme/members/u-admin", nil},
		{http.MethodPost, "/me/organizations/acme/invitations", map[string]any{"email": "x@acme.com"}},
		{http.MethodGet, "/me/organizations/acme/invitations", nil},
		{http.MethodDelete, "/me/organizations/acme/invitations/x@acme.com", nil},
	}
	for _, c := range cases {
		code, body := h.do(t, c.method, c.path, tok, c.body)
		if code != http.StatusForbidden {
			t.Errorf("%s %s status=%d, want 403 (%s)", c.method, c.path, code, body)
		}
	}
	// The admin's roster must be untouched by the blocked mutations.
	if m, err := h.members.Get(context.Background(), orgTenant, "u-admin"); err != nil || m.Role != core.TenantRoleAdmin {
		t.Fatalf("admin membership altered by blocked mutation: %+v %v", m, err)
	}
}

func TestOrgAdmin_PutMember_RoleChangeAndInviteOnly(t *testing.T) {
	h := newOrgHarness(t)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	h.seed(t, orgTenant, "u-member", core.TenantRoleMember)
	admin := h.token(t, "u-admin")
	ctx := context.Background()

	// Role change of an EXISTING member.
	if code, body := h.do(t, http.MethodPut, "/me/organizations/acme/members/u-member", admin, map[string]any{"role": "guest"}); code != http.StatusOK {
		t.Fatalf("role change status=%d (%s)", code, body)
	}
	if m, _ := h.members.Get(ctx, orgTenant, "u-member"); m == nil || m.Role != core.TenantRoleGuest {
		t.Fatalf("role not changed to guest: %+v", m)
	}

	// Invite-only growth: PUT of a NON-member target → 404 not_found (not a
	// direct add). New members join only via invitations.
	if code, body := h.do(t, http.MethodPut, "/me/organizations/acme/members/u-other", admin, map[string]any{"role": "member"}); code != http.StatusNotFound {
		t.Fatalf("non-member PUT status=%d, want 404 (%s)", code, body)
	}
	if _, err := h.members.Get(ctx, orgTenant, "u-other"); err == nil {
		t.Fatalf("non-member PUT created an unexpected membership")
	}

	// Co-admin grant: promoting an existing member to admin is allowed.
	if code, body := h.do(t, http.MethodPut, "/me/organizations/acme/members/u-member", admin, map[string]any{"role": "admin"}); code != http.StatusOK {
		t.Fatalf("co-admin grant status=%d (%s)", code, body)
	}
	if m, _ := h.members.Get(ctx, orgTenant, "u-member"); m == nil || m.Role != core.TenantRoleAdmin {
		t.Fatalf("co-admin grant did not stick: %+v", m)
	}
}

func TestOrgAdmin_LastAdminProtection(t *testing.T) {
	h := newOrgHarness(t)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin) // sole admin
	admin := h.token(t, "u-admin")
	ctx := context.Background()

	// Self-removal of the last admin → 409.
	if code, body := h.do(t, http.MethodDelete, "/me/organizations/acme/members/u-admin", admin, nil); code != http.StatusConflict {
		t.Fatalf("last-admin self-remove status=%d, want 409 (%s)", code, body)
	}
	if m, err := h.members.Get(ctx, orgTenant, "u-admin"); err != nil || m.Role != core.TenantRoleAdmin {
		t.Fatalf("last admin was removed despite 409: %+v %v", m, err)
	}
	// Self-demotion of the last admin → 409.
	if code, body := h.do(t, http.MethodPut, "/me/organizations/acme/members/u-admin", admin, map[string]any{"role": "member"}); code != http.StatusConflict {
		t.Fatalf("last-admin self-demote status=%d, want 409 (%s)", code, body)
	}

	// Once a second admin exists, both operations succeed.
	h.seed(t, orgTenant, "u-admin2", core.TenantRoleAdmin)
	if code, _ := h.do(t, http.MethodPut, "/me/organizations/acme/members/u-admin", admin, map[string]any{"role": "member"}); code != http.StatusOK {
		t.Fatalf("demote with a co-admin present should succeed, got %d", code)
	}
	admin2 := h.token(t, "u-admin2")
	if code, _ := h.do(t, http.MethodDelete, "/me/organizations/acme/members/u-admin2", admin2, nil); code != http.StatusConflict {
		// u-admin2 is now the ONLY admin again (u-admin was demoted).
		t.Fatalf("removing the now-sole admin should 409, got %d", code)
	}
}

func TestOrgAdmin_Invitations_FlowAndTokenSecrecy(t *testing.T) {
	sender := &captureInviteSender{}
	h := newOrgHarness(t, sso.WithInvitationSender(sender))
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	admin := h.token(t, "u-admin")

	// Issue.
	if code, body := h.do(t, http.MethodPost, "/me/organizations/acme/invitations", admin, map[string]any{"email": "bob@acme.com", "role": "member"}); code != http.StatusAccepted {
		t.Fatalf("issue invitation status=%d, want 202 (%s)", code, body)
	}
	if sender.token == "" || sender.tenant != "acme" {
		t.Fatalf("sender did not capture the invite: %+v", sender)
	}

	// List — never leaks the token.
	code, body := h.do(t, http.MethodGet, "/me/organizations/acme/invitations", admin, nil)
	if code != http.StatusOK {
		t.Fatalf("list invitations status=%d", code)
	}
	if bytes.Contains(body, []byte(sender.token)) {
		t.Fatalf("invitation list leaked the token value")
	}
	if !bytes.Contains(body, []byte("bob@acme.com")) {
		t.Fatalf("invitation list missing the recipient: %s", body)
	}

	// Revoke.
	if code, _ := h.do(t, http.MethodDelete, "/me/organizations/acme/invitations/bob@acme.com", admin, nil); code != http.StatusNoContent {
		t.Fatalf("revoke invitation status=%d, want 204", code)
	}
}

func TestOrgAdmin_Invitation_501WithoutSender(t *testing.T) {
	h := newOrgHarness(t) // no sender wired
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	if code, body := h.do(t, http.MethodPost, "/me/organizations/acme/invitations", h.token(t, "u-admin"), map[string]any{"email": "x@acme.com"}); code != http.StatusNotImplemented {
		t.Fatalf("issue without sender status=%d, want 501 (%s)", code, body)
	}
}

func TestOrgAdmin_SuspendedTenant_MutationsRefusedReadsAllowed(t *testing.T) {
	tstore := tenantmemory.New()
	_ = tstore.PutTenant(context.Background(), &tenant.Tenant{
		ID: orgTenant, Slug: orgTenant, Name: orgTenant, Status: tenant.StatusSuspended,
	})
	h := newOrgHarness(t,
		sso.WithInvitationSender(&captureInviteSender{}),
		sso.WithTenantStore(tstore),
		sso.WithTenantSuspensionCheck(time.Minute),
	)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	h.seed(t, orgTenant, "u-member", core.TenantRoleMember)
	admin := h.token(t, "u-admin")

	// Read is allowed on a suspended tenant.
	if code, body := h.do(t, http.MethodGet, "/me/organizations/acme/members", admin, nil); code != http.StatusOK {
		t.Fatalf("read on suspended tenant status=%d, want 200 (%s)", code, body)
	}
	// Mutations are refused.
	muts := []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/me/organizations/acme/members/u-member", map[string]any{"role": "guest"}},
		{http.MethodDelete, "/me/organizations/acme/members/u-member", nil},
		{http.MethodPost, "/me/organizations/acme/invitations", map[string]any{"email": "z@acme.com"}},
	}
	for _, m := range muts {
		if code, body := h.do(t, m.method, m.path, admin, m.body); code != http.StatusForbidden {
			t.Errorf("%s %s on suspended tenant status=%d, want 403 (%s)", m.method, m.path, code, body)
		}
	}
}

func TestOrgAdmin_Audit_ActorSubjectAndViaOrgAdmin(t *testing.T) {
	h := newOrgHarness(t)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	h.seed(t, orgTenant, "u-member", core.TenantRoleMember)

	if code, _ := h.do(t, http.MethodPut, "/me/organizations/acme/members/u-member", h.token(t, "u-admin"), map[string]any{"role": "guest"}); code != http.StatusOK {
		t.Fatalf("role change should succeed")
	}
	events, _ := h.sink.Query(context.Background(), audit.Query{Type: audit.EventAdminTenantMemberAdded})
	if len(events) == 0 {
		t.Fatalf("no member-added audit event recorded")
	}
	e := events[0]
	if e.ActorID != "u-admin" {
		t.Errorf("audit ActorID=%q, want the delegated admin subject u-admin", e.ActorID)
	}
	if e.Metadata["via"] != "org_admin" {
		t.Errorf("audit via=%q, want org_admin", e.Metadata["via"])
	}
	if e.Metadata["tenant_id"] != orgTenant {
		t.Errorf("audit tenant_id=%q, want %s", e.Metadata["tenant_id"], orgTenant)
	}
}

func TestOrgAdmin_UnauthenticatedChallenged(t *testing.T) {
	h := newOrgHarness(t)
	h.seed(t, orgTenant, "u-admin", core.TenantRoleAdmin)
	if code, _ := h.do(t, http.MethodGet, "/me/organizations/acme/members", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d, want 401", code)
	}
}
