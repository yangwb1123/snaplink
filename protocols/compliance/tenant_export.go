package compliance

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

// TenantExportFormatVersion is stamped into every TenantExport and checked by
// VerifyTenantExport, mirroring auditexport.FormatVersion — bump only on a
// breaking layout change so an old reader rejects a newer bundle loudly
// instead of misreading a mismatched schema.
const TenantExportFormatVersion = 1

// TenantExporter assembles a TENANT-scoped export bundle: everything the
// server holds for one tenant, suitable for offboarding a customer or
// migrating them to a new environment. It is the tenant-scoped sibling of
// Exporter (which is subject/user-scoped, for GDPR Art. 15): where Exporter
// answers "what does the server know about user X", TenantExporter answers
// "what does the server know about tenant X".
//
// Every field is optional except TenantID at call time — a nil dependency
// means that resource type is skipped in the bundle (recorded via its
// absence, not an error), so a deployment that only wires a ClientStore
// still gets a useful (if partial) export. This mirrors
// interfaces/snapshot.Snapshotter's per-category nil-gating, applied to a
// single tenant's slice of each store instead of the whole store.
//
// Resource sections deliberately reuse each store's EXISTING tenant-scoped
// list method (ListByTenant / ByTenant) rather than inventing a new query
// path — see the per-resource export* methods below.
type TenantExporter struct {
	// Clients lists this tenant's registered clients. Only used when the
	// concrete store implements core.TenantScopedClientStore (the memory and
	// sqlite backends both do); other backends silently skip this section.
	Clients core.ClientStore
	// Users resolves each roster member's full profile (redacted — see
	// redactCredentialAttrs). Requires Memberships to enumerate user IDs;
	// there is no tenant-scoped UserProvider query.
	Users core.UserProvider
	// Sessions summarizes (never lists raw) this tenant's sessions. Only
	// used when the concrete manager implements core.SessionTenantLister.
	Sessions core.SessionManager
	// Memberships is the tenant roster — the anchor for both the members
	// section and the fan-out to Users.
	Memberships core.TenantUserStore
	// Invitations lists pending org invitations (never their tokens — see
	// core.Invitation's doc comment).
	Invitations core.InvitationStore
	// Connections lists this tenant's B2B enterprise IdP connections
	// (config secrets redacted — see toTenantExportConnection).
	Connections connections.Store
	// Permissions enumerates roles + assignments for each of this tenant's
	// clients (mirrors interfaces/snapshot.Snapshotter.exportRoles/
	// exportAssignments).
	Permissions permissions.Provider
	// Auditor supplies a bounded audit-event SUMMARY (counts by type/
	// outcome/client/provider), never the raw events — a full event dump is
	// platform/audit/auditexport's job, not this bundle's. Only used when
	// the wired Sink implements audit.FacetQuerier.
	Auditor *audit.Recorder
}

// TenantExport is the offboarding/migration bundle for one tenant —
// JSON-marshalable as-is for delivery to an admin. Sections are omitted
// (nil slice) rather than present-but-empty when their backing store was
// never wired, so a recipient can tell "no data" apart from "not exported".
type TenantExport struct {
	FormatVersion int       `json:"format_version"`
	TenantID      string    `json:"tenant_id"`
	GeneratedAt   time.Time `json:"generated_at"`

	Clients     []*core.Client            `json:"clients,omitempty"`
	Members     []*core.TenantMembership  `json:"members,omitempty"`
	Users       []*core.User              `json:"users,omitempty"`
	Invitations []*core.Invitation        `json:"invitations,omitempty"`
	Connections []tenantExportConnection  `json:"connections,omitempty"`
	Roles       []TenantClientRoles       `json:"roles,omitempty"`
	Assignments []TenantClientAssignments `json:"assignments,omitempty"`

	SessionsSummary TenantSessionsSummary `json:"sessions_summary"`
	// AuditSummary is nil when no Auditor was wired or its Sink doesn't
	// support facet aggregation — distinguishing "no audit events" (a
	// non-nil *audit.Facets with Total==0) from "audit summary unavailable".
	AuditSummary *audit.Facets `json:"audit_summary,omitempty"`

	Manifest TenantExportManifest `json:"manifest"`
}

// TenantClientRoles pairs one client's role catalogue with its ID — the
// tenant-export-local equivalent of interfaces/snapshot.ClientRoles
// (duplicated rather than imported: protocols/ may not import interfaces/,
// see architecture_layer_test.go's layer ranks).
type TenantClientRoles struct {
	ClientID string             `json:"client_id"`
	Roles    []permissions.Role `json:"roles"`
}

// TenantClientAssignments pairs one client's user-role assignments with its
// ID — the tenant-export-local equivalent of interfaces/snapshot.ClientAssignments.
type TenantClientAssignments struct {
	ClientID    string                   `json:"client_id"`
	Assignments []permissions.Assignment `json:"assignments"`
}

// TenantSessionsSummary is the aggregated (never raw) session picture for a
// tenant. Sessions are ephemeral, environment-local state — not portable
// across a migration and not needed for an offboarding record — so the
// bundle carries counts, not session IDs.
type TenantSessionsSummary struct {
	// Supported is false when the wired SessionManager doesn't implement
	// core.SessionTenantLister — distinguishes "zero sessions" from
	// "couldn't ask".
	Supported bool `json:"supported"`
	Total     int  `json:"total"`
	Active    int  `json:"active"`
	Revoked   int  `json:"revoked"`
}

// BuildTenantExport collects tenantID's data across every wired store into a
// TenantExport bundle. Best-effort like Exporter.ExportSubject: a failing
// store is recorded in the returned (joined) error but does not abort the
// others, so the caller still gets a partial bundle rather than nothing —
// an offboarding export half-succeeding is more useful to an admin than one
// that aborts entirely on the first store hiccup. The bundle is always
// non-nil.
func (e *TenantExporter) BuildTenantExport(ctx context.Context, tenantID string) (*TenantExport, error) {
	if tenantID == "" {
		return nil, errors.New("compliance: empty tenant id")
	}
	exp := &TenantExport{
		FormatVersion: TenantExportFormatVersion,
		TenantID:      tenantID,
		GeneratedAt:   time.Now().UTC(),
	}
	var errs []error
	record := func(section string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", section, err))
		}
	}

	clientIDs, err := e.exportClients(ctx, exp, tenantID)
	record("clients", err)
	record("members", e.exportMembers(ctx, exp, tenantID))
	record("invitations", e.exportInvitations(ctx, exp, tenantID))
	record("connections", e.exportConnections(ctx, exp, tenantID))
	record("permissions", e.exportPermissions(ctx, exp, clientIDs))
	record("sessions", e.exportSessionsSummary(ctx, exp, tenantID))
	record("audit", e.exportAuditSummary(ctx, exp, tenantID))

	exp.Manifest = buildTenantExportManifest(exp)
	return exp, errors.Join(errs...)
}

// exportClients lists tenantID's clients (when the store supports
// tenant-scoped listing) and returns their IDs, which exportPermissions
// needs to fan out roles/assignments per client. Each client is a
// REDACTED shallow copy — see redactClientSecrets.
func (e *TenantExporter) exportClients(ctx context.Context, exp *TenantExport, tenantID string) ([]string, error) {
	lister, ok := e.Clients.(core.TenantScopedClientStore)
	if !ok {
		return nil, nil
	}
	clients, err := lister.ListByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	ids := make([]string, 0, len(clients))
	out := make([]*core.Client, 0, len(clients))
	for _, c := range clients {
		if c == nil {
			continue
		}
		ids = append(ids, c.ID)
		out = append(out, redactClientSecrets(c))
	}
	exp.Clients = out
	return ids, nil
}

// exportMembers lists tenantID's roster and, for each member, resolves the
// full (redacted) user profile. Unlike the admin roster view
// (interfaces/admin.HandleAdminListTenantMembers, which returns only role +
// timestamps), an offboarding/migration export needs enough per-user data to
// reconstruct accounts elsewhere.
func (e *TenantExporter) exportMembers(ctx context.Context, exp *TenantExport, tenantID string) error {
	if e.Memberships == nil {
		return nil
	}
	members, err := e.Memberships.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	sort.Slice(members, func(i, j int) bool { return members[i].UserID < members[j].UserID })
	exp.Members = members
	if e.Users == nil {
		return nil
	}
	var errs []error
	users := make([]*core.User, 0, len(members))
	for _, m := range members {
		if m == nil {
			continue
		}
		u, err := e.Users.GetByID(ctx, m.UserID)
		if err != nil {
			errs = append(errs, fmt.Errorf("user %s: %w", m.UserID, err))
			continue
		}
		users = append(users, redactCredentialAttrs(u))
	}
	exp.Users = users
	return errors.Join(errs...)
}

// exportInvitations lists tenantID's pending org invitations. Invitation's
// Token field carries json:"-" (it is a live credential — see
// core.Invitation's doc comment), so embedding the store's result directly
// is already oracle-safe with no separate redaction step.
func (e *TenantExporter) exportInvitations(ctx context.Context, exp *TenantExport, tenantID string) error {
	if e.Invitations == nil {
		return nil
	}
	invs, err := e.Invitations.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	exp.Invitations = invs
	return nil
}

// exportConnections lists tenantID's B2B enterprise connections, redacting
// credential-shaped Config keys — see toTenantExportConnection.
func (e *TenantExporter) exportConnections(ctx context.Context, exp *TenantExport, tenantID string) error {
	if e.Connections == nil {
		return nil
	}
	conns, err := e.Connections.ByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	sort.Slice(conns, func(i, j int) bool { return conns[i].ID < conns[j].ID })
	out := make([]tenantExportConnection, 0, len(conns))
	for _, c := range conns {
		if c == nil {
			continue
		}
		out = append(out, toTenantExportConnection(c))
	}
	exp.Connections = out
	return nil
}

// exportPermissions enumerates roles + assignments for every client owned by
// this tenant. Mirrors interfaces/snapshot.Snapshotter.exportRoles /
// exportAssignments almost exactly (same Provider calls, per-client
// fan-out); duplicated rather than shared because protocols/ may not import
// interfaces/ (architecture_layer_test.go).
func (e *TenantExporter) exportPermissions(ctx context.Context, exp *TenantExport, clientIDs []string) error {
	if e.Permissions == nil || len(clientIDs) == 0 {
		return nil
	}
	var errs []error
	for _, cid := range clientIDs {
		roles, err := e.Permissions.ListAllRoles(ctx, cid)
		if err != nil {
			errs = append(errs, fmt.Errorf("roles[%s]: %w", cid, err))
		} else if len(roles) > 0 {
			exp.Roles = append(exp.Roles, TenantClientRoles{ClientID: cid, Roles: roles})
		}
		assigns, err := e.Permissions.ListAssignments(ctx, cid)
		if err != nil {
			errs = append(errs, fmt.Errorf("assignments[%s]: %w", cid, err))
		} else if len(assigns) > 0 {
			exp.Assignments = append(exp.Assignments, TenantClientAssignments{ClientID: cid, Assignments: assigns})
		}
	}
	return errors.Join(errs...)
}

// exportSessionsSummary counts (never lists) tenantID's sessions. Only runs
// when the wired SessionManager implements core.SessionTenantLister;
// otherwise SessionsSummary.Supported stays false.
func (e *TenantExporter) exportSessionsSummary(ctx context.Context, exp *TenantExport, tenantID string) error {
	lister, ok := e.Sessions.(core.SessionTenantLister)
	if !ok {
		return nil
	}
	sessions, err := lister.ListByTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	summary := TenantSessionsSummary{Supported: true, Total: len(sessions)}
	now := time.Now()
	for _, s := range sessions {
		if s == nil {
			continue
		}
		if s.Revoked {
			summary.Revoked++
			continue
		}
		if s.ExpiresAt.After(now) {
			summary.Active++
		}
	}
	exp.SessionsSummary = summary
	return nil
}

// exportAuditSummary computes a bounded, aggregated audit picture for
// tenantID via the Sink's optional FacetQuerier extension (counts by type /
// outcome / client / provider) — never the raw events, which would make this
// bundle an unbounded PII dump duplicating platform/audit/auditexport's job.
// Silently skipped (not an error) when no Auditor is wired or its Sink
// doesn't support facets, matching the MenuLister-style optional-capability
// pattern used throughout this codebase.
func (e *TenantExporter) exportAuditSummary(ctx context.Context, exp *TenantExport, tenantID string) error {
	if e.Auditor == nil {
		return nil
	}
	fq, ok := e.Auditor.Sink().(audit.FacetQuerier)
	if !ok {
		return nil
	}
	facets, err := fq.Facets(ctx, audit.Query{TenantID: tenantID})
	if err != nil {
		return err
	}
	exp.AuditSummary = facets
	return nil
}
