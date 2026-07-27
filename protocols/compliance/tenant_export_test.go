package compliance_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
)

// buildFullTenantExporter wires every optional dependency and seeds BOTH the
// target tenant "acme" and an unrelated tenant "other" — so assertions can
// prove no cross-tenant data leaked into the "acme" bundle, not just that
// "acme" data is present.
func buildFullTenantExporter(t *testing.T) *compliance.TenantExporter {
	t.Helper()
	ctx := context.Background()

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&core.Client{ID: "acme-app", Secret: "shh", RegistrationAccessToken: "rat", TenantID: "acme", Active: true})
	clients.AddSeed(&core.Client{ID: "other-app", Secret: "shh2", TenantID: "other", Active: true})

	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{
		ID: "u-alice", Email: "alice@acme.example",
		Attributes: map[string]string{"password_hash": "bcrypt$x", "department": "eng"},
	}); err != nil {
		t.Fatalf("seed alice: %v", err)
	}
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u-bob", Email: "bob@other.example"}); err != nil {
		t.Fatalf("seed bob: %v", err)
	}

	members := defaultimpl.NewMemoryTenantUserStore()
	if err := members.Add(ctx, &core.TenantMembership{TenantID: "acme", UserID: "u-alice", Role: core.TenantRoleAdmin, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if err := members.Add(ctx, &core.TenantMembership{TenantID: "other", UserID: "u-bob", Role: core.TenantRoleMember, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed other membership: %v", err)
	}

	invitations := defaultimpl.NewMemoryInvitationStore()
	if err := invitations.Issue(ctx, &core.Invitation{Token: "live-token-value", TenantID: "acme", Email: "new@acme.example", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("seed invitation: %v", err)
	}
	if err := invitations.Issue(ctx, &core.Invitation{Token: "other-token", TenantID: "other", Email: "x@other.example", Role: core.TenantRoleMember, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("seed other invitation: %v", err)
	}

	conns := connections.NewMemoryStore()
	if err := conns.Upsert(ctx, &connections.Connection{
		ID: "acme-idp", TenantID: "acme", Type: connections.TypeOIDC, DisplayName: "Acme Okta",
		Domains: []string{"acme.example"}, Enabled: true,
		Config: map[string]string{"oidc_issuer": "https://okta.acme.example", "oidc_client_secret": "super-secret"},
	}); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	if err := conns.Upsert(ctx, &connections.Connection{ID: "other-idp", TenantID: "other", Type: connections.TypeSAML, Enabled: true}); err != nil {
		t.Fatalf("seed other connection: %v", err)
	}

	perms := permissions.NewMemoryProvider()
	if err := perms.AddRole(ctx, "acme-app", permissions.Role{Code: "viewer", Permissions: []string{"user:read"}}); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	if err := perms.AssignRoles(ctx, "u-alice", "acme-app", []string{"viewer"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	if err := perms.AddRole(ctx, "other-app", permissions.Role{Code: "owner", Permissions: []string{"*"}}); err != nil {
		t.Fatalf("seed other role: %v", err)
	}

	sessions := defaultimpl.NewMemorySessionManager()
	if _, err := sessions.CreateWithMeta(ctx, "u-alice", core.SessionMeta{TenantID: "acme"}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	if _, err := sessions.CreateWithMeta(ctx, "u-alice", core.SessionMeta{TenantID: "acme"}); err != nil {
		t.Fatalf("seed second session: %v", err)
	}
	if _, err := sessions.CreateWithMeta(ctx, "u-bob", core.SessionMeta{TenantID: "other"}); err != nil {
		t.Fatalf("seed other session: %v", err)
	}

	sink := audit.NewMemorySink(100)
	rec := audit.New(sink)
	rec.Record(ctx, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, TenantID: "acme", Timestamp: time.Now()})
	rec.Record(ctx, &audit.Event{Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, TenantID: "acme", Timestamp: time.Now()})
	rec.Record(ctx, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, TenantID: "other", Timestamp: time.Now()})

	return &compliance.TenantExporter{
		Clients: clients, Users: users, Sessions: sessions, Memberships: members,
		Invitations: invitations, Connections: conns, Permissions: perms, Auditor: rec,
	}
}

func TestBuildTenantExport_FullBundleScopedToOneTenant(t *testing.T) {
	t.Parallel()
	exp := buildFullTenantExporter(t)
	bundle, err := exp.BuildTenantExport(context.Background(), "acme")
	if err != nil {
		t.Fatalf("BuildTenantExport: %v", err)
	}
	if bundle.TenantID != "acme" || bundle.FormatVersion != compliance.TenantExportFormatVersion {
		t.Fatalf("bundle header = %+v", bundle)
	}

	// Clients: only acme's, secrets redacted.
	if len(bundle.Clients) != 1 || bundle.Clients[0].ID != "acme-app" {
		t.Fatalf("clients = %+v, want exactly acme-app", bundle.Clients)
	}
	if bundle.Clients[0].Secret != "" || bundle.Clients[0].RegistrationAccessToken != "" {
		t.Errorf("client secret material not redacted: %+v", bundle.Clients[0])
	}

	// Members + Users: only alice, credential attrs stripped, profile kept.
	if len(bundle.Members) != 1 || bundle.Members[0].UserID != "u-alice" {
		t.Fatalf("members = %+v, want exactly u-alice", bundle.Members)
	}
	if len(bundle.Users) != 1 || bundle.Users[0].ID != "u-alice" {
		t.Fatalf("users = %+v, want exactly u-alice", bundle.Users)
	}
	if _, leaked := bundle.Users[0].Attributes["password_hash"]; leaked {
		t.Error("password_hash leaked into tenant export")
	}
	if bundle.Users[0].Attributes["department"] != "eng" {
		t.Error("non-credential attribute was stripped along with credentials")
	}

	// Invitations: only acme's, and the live token never appears anywhere
	// on the wire (json:"-" on core.Invitation.Token).
	if len(bundle.Invitations) != 1 || bundle.Invitations[0].Email != "new@acme.example" {
		t.Fatalf("invitations = %+v, want exactly the acme invite", bundle.Invitations)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	if strings.Contains(string(raw), "live-token-value") || strings.Contains(string(raw), "other-token") {
		t.Error("invitation token leaked into the serialized bundle")
	}

	// Connections: only acme's, secret-shaped config key redacted, benign one kept.
	if len(bundle.Connections) != 1 || bundle.Connections[0].ID != "acme-idp" {
		t.Fatalf("connections = %+v, want exactly acme-idp", bundle.Connections)
	}
	if _, leaked := bundle.Connections[0].Config["oidc_client_secret"]; leaked {
		t.Error("connection client secret leaked into tenant export")
	}
	if bundle.Connections[0].Config["oidc_issuer"] != "https://okta.acme.example" {
		t.Error("non-secret connection config was stripped along with the secret")
	}
	if strings.Contains(string(raw), "super-secret") {
		t.Error("connection secret leaked into the serialized bundle")
	}

	// Roles/assignments: only acme-app's.
	if len(bundle.Roles) != 1 || bundle.Roles[0].ClientID != "acme-app" {
		t.Fatalf("roles = %+v, want exactly acme-app", bundle.Roles)
	}
	if len(bundle.Assignments) != 1 || bundle.Assignments[0].ClientID != "acme-app" {
		t.Fatalf("assignments = %+v, want exactly acme-app", bundle.Assignments)
	}

	// Sessions: summarized, not listed — both of alice's, none of bob's (other tenant).
	if !bundle.SessionsSummary.Supported {
		t.Fatal("sessions summary should be supported by the memory session manager")
	}
	if bundle.SessionsSummary.Total != 2 || bundle.SessionsSummary.Active != 2 || bundle.SessionsSummary.Revoked != 0 {
		t.Errorf("sessions summary = %+v, want total=2 active=2 revoked=0", bundle.SessionsSummary)
	}

	// Audit: aggregated counts scoped to acme only (2 events, not 3).
	if bundle.AuditSummary == nil {
		t.Fatal("expected an audit summary")
	}
	if bundle.AuditSummary.Total != 2 {
		t.Errorf("audit summary total = %d, want 2 (acme-only)", bundle.AuditSummary.Total)
	}

	// Manifest: counts line up, checksum verifies.
	if bundle.Manifest.Sections["clients"] != 1 || bundle.Manifest.Sections["users"] != 1 {
		t.Errorf("manifest sections = %+v", bundle.Manifest.Sections)
	}
	if bundle.Manifest.Checksum == "" {
		t.Error("manifest checksum is empty")
	}
	if err := compliance.VerifyTenantExport(bundle); err != nil {
		t.Errorf("VerifyTenantExport: %v", err)
	}
}

func TestBuildTenantExport_EmptyTenantID(t *testing.T) {
	t.Parallel()
	exp := &compliance.TenantExporter{}
	if _, err := exp.BuildTenantExport(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty tenant id")
	}
}

func TestBuildTenantExport_NilDependenciesSkipSections(t *testing.T) {
	t.Parallel()
	exp := &compliance.TenantExporter{}
	bundle, err := exp.BuildTenantExport(context.Background(), "acme")
	if err != nil {
		t.Fatalf("BuildTenantExport with no deps should not error: %v", err)
	}
	if len(bundle.Clients) != 0 || len(bundle.Members) != 0 || len(bundle.Users) != 0 ||
		len(bundle.Invitations) != 0 || len(bundle.Connections) != 0 ||
		len(bundle.Roles) != 0 || len(bundle.Assignments) != 0 {
		t.Errorf("expected every section empty, got %+v", bundle)
	}
	if bundle.SessionsSummary.Supported {
		t.Error("sessions summary should be unsupported with no SessionManager wired")
	}
	if bundle.AuditSummary != nil {
		t.Error("audit summary should be nil with no Auditor wired")
	}
	if _, ok := bundle.Manifest.Sections["audit_events"]; ok {
		t.Error("audit_events section should be absent, not zero, when unavailable")
	}
	if err := compliance.VerifyTenantExport(bundle); err != nil {
		t.Errorf("VerifyTenantExport on the empty bundle: %v", err)
	}
}

// failingMembershipStore fails ListByTenant so BuildTenantExport's
// best-effort contract can be exercised without a real store outage.
type failingMembershipStore struct{ core.TenantUserStore }

func (failingMembershipStore) ListByTenant(context.Context, string) ([]*core.TenantMembership, error) {
	return nil, errors.New("membership store unavailable")
}

func TestBuildTenantExport_PartialFailureIsBestEffort(t *testing.T) {
	t.Parallel()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&core.Client{ID: "acme-app", TenantID: "acme", Active: true})
	exp := &compliance.TenantExporter{
		Clients:     clients,
		Memberships: failingMembershipStore{},
	}
	bundle, err := exp.BuildTenantExport(context.Background(), "acme")
	if err == nil {
		t.Fatal("expected aggregated error from the failing membership store")
	}
	if bundle == nil {
		t.Fatal("expected a non-nil partial bundle")
	}
	if len(bundle.Clients) != 1 {
		t.Errorf("partial bundle should still carry the clients section: %+v", bundle.Clients)
	}
}

func TestVerifyTenantExport_DetectsTamper(t *testing.T) {
	t.Parallel()
	exp := &compliance.TenantExporter{}
	bundle, err := exp.BuildTenantExport(context.Background(), "acme")
	if err != nil {
		t.Fatalf("BuildTenantExport: %v", err)
	}
	bundle.Clients = append(bundle.Clients, &core.Client{ID: "injected"})
	if err := compliance.VerifyTenantExport(bundle); err == nil {
		t.Fatal("expected checksum mismatch after tampering with the bundle")
	}
}

// fakeSessionLister exercises exportSessionsSummary's active/revoked/expired
// counting in isolation from a real backend's semantics (the memory
// SessionManager's Destroy hard-deletes rather than marking Revoked, so it
// alone can't drive the Revoked branch — see
// TestBuildTenantExport_FullBundleScopedToOneTenant).
type fakeSessionLister struct {
	core.SessionManager
	sessions []*core.Session
}

func (f fakeSessionLister) ListByTenant(context.Context, string) ([]*core.Session, error) {
	return f.sessions, nil
}

func TestBuildTenantExport_SessionsSummaryCountsRevokedAndExpired(t *testing.T) {
	t.Parallel()
	now := time.Now()
	exp := &compliance.TenantExporter{
		Sessions: fakeSessionLister{sessions: []*core.Session{
			{ID: "s1", Revoked: false, ExpiresAt: now.Add(time.Hour)},  // active
			{ID: "s2", Revoked: true, ExpiresAt: now.Add(time.Hour)},   // revoked
			{ID: "s3", Revoked: false, ExpiresAt: now.Add(-time.Hour)}, // expired, not revoked, not active
		}},
	}
	bundle, err := exp.BuildTenantExport(context.Background(), "acme")
	if err != nil {
		t.Fatalf("BuildTenantExport: %v", err)
	}
	want := compliance.TenantSessionsSummary{Supported: true, Total: 3, Active: 1, Revoked: 1}
	if bundle.SessionsSummary != want {
		t.Errorf("sessions summary = %+v, want %+v", bundle.SessionsSummary, want)
	}
}

func TestVerifyTenantExport_NilBundle(t *testing.T) {
	t.Parallel()
	if err := compliance.VerifyTenantExport(nil); err == nil {
		t.Fatal("expected error for nil bundle")
	}
}
