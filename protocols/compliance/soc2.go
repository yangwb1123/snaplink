package compliance

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// DefaultSOC2Window is how far back the change-management / access-revocation
// sections look when SOC2Options.Since is zero.
const DefaultSOC2Window = 90 * 24 * time.Hour

// DefaultSOC2SectionLimit caps the number of audit entries surfaced per
// section when SOC2Options.Limit is zero — a storm/memory-pressure guard,
// mirroring audit.DefaultQueryLimit.
const DefaultSOC2SectionLimit = 500

// changeManagementEventTypes are the admin-mutation events that count as SOC2
// "change management" evidence. A curated list rather than a blanket
// "admin_" prefix match: some admin_* events (EventAdminGRPCCalled) fire on
// EVERY gated RPC, not just a state change, and would drown the pack in noise.
var changeManagementEventTypes = []audit.EventType{
	audit.EventAdminClientCreated, audit.EventAdminClientUpdated, audit.EventAdminClientDeleted,
	audit.EventAdminClientSecretRotated,
	audit.EventAdminUserCreated, audit.EventAdminUserUpdated, audit.EventAdminUserDeleted,
	audit.EventAdminUserEmailChanged,
	audit.EventAdminConnectionUpserted, audit.EventAdminConnectionDeleted,
	audit.EventAdminTenantMemberAdded, audit.EventAdminTenantMemberRemoved,
	audit.EventAdminRoleAdded, audit.EventAdminRoleUpdated, audit.EventAdminRoleRemoved,
	audit.EventAdminRoleAssigned, audit.EventAdminRoleUnassigned, audit.EventAdminMenusUpdated,
	audit.EventAdminTenantCreated, audit.EventAdminTenantUpdated, audit.EventAdminTenantDeleted,
	audit.EventAdminTenantStatusChanged,
	audit.EventAdminDomainCreated, audit.EventAdminDomainUpdated, audit.EventAdminDomainDeleted,
	audit.EventAdminCredentialCompromised,
	audit.EventAdminPasswordReset, audit.EventAdminAccountUnlocked,
}

// accessRevocationEventTypes are the token/session/credential revocation
// events surfaced as SOC2 "access revocation" evidence (CC6.2/CC6.3).
var accessRevocationEventTypes = []audit.EventType{
	audit.EventTokenRevoked, audit.EventAdminTokenRevoked,
	audit.EventTenantTokensRevoked, audit.EventTenantSessionsRevoked,
	audit.EventConsentRevoked, audit.EventAdminConsentRevoked,
	audit.EventAdminDeviceSecretsRevoked, audit.EventAdminMFAFactorRemoved,
	audit.EventAdminPasswordResetTokensRevoked, audit.EventAdminEmailChangeTokensRevoked,
	audit.EventAdminBreakGlassRevoked, audit.EventPartialRevokeFailure,
}

// SOC2Reporter assembles a SOC2 evidence pack from state ALREADY recorded
// elsewhere: the permissions store's current role assignments (CC6.1 access
// review) and the audit trail's admin-mutation + revocation events (CC8.1
// change management / CC6.2-CC6.3 access revocation). It composes existing
// SPIs the same way Eraser/Exporter do — no new storage, no new tracking, and
// byte-identical to a build that never calls Generate.
type SOC2Reporter struct {
	// Permissions supplies the current role-assignment snapshot (access
	// review). Nil ⇒ that section is empty (Skipped notes why).
	Permissions permissions.Provider
	// Clients enumerates the client (application) IDs Permissions.ListAssignments
	// is scoped by — assignments are per (user, client), so every client is
	// walked the same way Eraser walks Clients for refresh-token revocation.
	Clients core.ClientStore
	// Audit is the underlying Sink the change-management + access-revocation
	// sections query. Nil ⇒ both sections are empty.
	Audit audit.Sink
}

// SOC2Options tunes one Generate call.
type SOC2Options struct {
	// Since bounds the change-management / access-revocation sections
	// (inclusive). Zero ⇒ time.Now().Add(-DefaultSOC2Window).
	Since time.Time
	// Limit caps entries surfaced PER SECTION. <=0 ⇒ DefaultSOC2SectionLimit.
	Limit int
}

// ClientRoleAssignments is one client (application)'s current role-assignment
// snapshot — the access-review evidence unit.
type ClientRoleAssignments struct {
	ClientID    string                   `json:"client_id"`
	Assignments []permissions.Assignment `json:"assignments"`
}

// SOC2Evidence is the assembled evidence pack, JSON-marshalable as-is for
// delivery/download as the operator's evidence artifact.
type SOC2Evidence struct {
	GeneratedAt time.Time `json:"generated_at"`
	Since       time.Time `json:"since"`

	// AccessReview: current admin role assignments, one entry per client
	// that has at least one assignment (CC6.1).
	AccessReview []ClientRoleAssignments `json:"access_review"`
	// ChangeManagement: admin mutations recorded in the audit trail since
	// Since (CC8.1).
	ChangeManagement []*audit.Event `json:"change_management"`
	// AccessRevocation: token/session/credential revocation events recorded
	// in the audit trail since Since (CC6.2/CC6.3).
	AccessRevocation []*audit.Event `json:"access_revocation"`

	// Skipped names sections that produced no data because their backing SPI
	// wasn't wired.
	Skipped []string `json:"skipped,omitempty"`
	// Errors collects best-effort per-section failures; a failing section
	// does not abort the others.
	Errors []string `json:"errors,omitempty"`
}

// Generate assembles the evidence pack. Best-effort like Eraser/Exporter: a
// failing section is recorded in Errors but never aborts the others, so a
// single store outage still yields a partial (clearly-marked) pack rather
// than nothing.
func (r *SOC2Reporter) Generate(ctx context.Context, opts SOC2Options) (*SOC2Evidence, error) {
	since, limit := soc2Defaults(opts)
	ev := &SOC2Evidence{GeneratedAt: time.Now().UTC(), Since: since}

	r.buildAccessReview(ctx, ev)
	r.buildChangeManagement(ctx, ev, since, limit)
	r.buildAccessRevocation(ctx, ev, since, limit)

	if len(ev.Errors) > 0 {
		return ev, fmt.Errorf("soc2 evidence: %d section error(s)", len(ev.Errors))
	}
	return ev, nil
}

// soc2Defaults resolves the zero-value defaults for Since/Limit.
func soc2Defaults(opts SOC2Options) (time.Time, int) {
	since := opts.Since
	if since.IsZero() {
		since = time.Now().Add(-DefaultSOC2Window)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultSOC2SectionLimit
	}
	return since, limit
}

// buildAccessReview walks every registered client and lists its current role
// assignments (CC6.1). A client with zero assignments is omitted, not zeroed
// in, so an empty pack reads as "nobody has roles" rather than N empty rows.
func (r *SOC2Reporter) buildAccessReview(ctx context.Context, ev *SOC2Evidence) {
	if r.Permissions == nil || r.Clients == nil {
		ev.Skipped = append(ev.Skipped, "access_review(not wired)")
		return
	}
	clients, err := r.Clients.List(ctx)
	if err != nil {
		ev.Errors = append(ev.Errors, fmt.Sprintf("list clients: %v", err))
		return
	}
	sort.Slice(clients, func(i, j int) bool { return clients[i].ID < clients[j].ID })
	for _, c := range clients {
		assignments, err := r.Permissions.ListAssignments(ctx, c.ID)
		if err != nil {
			ev.Errors = append(ev.Errors, fmt.Sprintf("list assignments (client=%s): %v", c.ID, err))
			continue
		}
		if len(assignments) == 0 {
			continue
		}
		ev.AccessReview = append(ev.AccessReview, ClientRoleAssignments{ClientID: c.ID, Assignments: assignments})
	}
}

func (r *SOC2Reporter) buildChangeManagement(ctx context.Context, ev *SOC2Evidence, since time.Time, limit int) {
	events, errs := r.queryByTypes(ctx, changeManagementEventTypes, since, limit)
	if events == nil && errs == nil {
		ev.Skipped = append(ev.Skipped, "change_management(not wired)")
		return
	}
	ev.ChangeManagement = events
	ev.Errors = append(ev.Errors, errs...)
}

func (r *SOC2Reporter) buildAccessRevocation(ctx context.Context, ev *SOC2Evidence, since time.Time, limit int) {
	events, errs := r.queryByTypes(ctx, accessRevocationEventTypes, since, limit)
	if events == nil && errs == nil {
		ev.Skipped = append(ev.Skipped, "access_revocation(not wired)")
		return
	}
	ev.AccessRevocation = events
	ev.Errors = append(ev.Errors, errs...)
}

// queryByTypes queries r.Audit once per event type (the Sink API filters by a
// single Type) since the audit Sink has no "type IN (...)" query, merges,
// sorts newest-first, and truncates to limit. Returns (nil, nil) only when
// r.Audit is nil, so callers can distinguish "not wired" from "wired but
// found nothing" (a non-nil empty slice). A per-type query failure is
// collected and the remaining types are still tried — best-effort, matching
// Eraser/Exporter.
func (r *SOC2Reporter) queryByTypes(ctx context.Context, types []audit.EventType, since time.Time, limit int) ([]*audit.Event, []string) {
	if r.Audit == nil {
		return nil, nil
	}
	events := []*audit.Event{}
	var errs []string
	for _, t := range types {
		got, err := r.Audit.Query(ctx, audit.Query{Type: t, Since: since, Limit: limit})
		if err != nil {
			errs = append(errs, fmt.Sprintf("query %s: %v", t, err))
			continue
		}
		events = append(events, got...)
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.After(events[j].Timestamp) })
	if len(events) > limit {
		events = events[:limit]
	}
	return events, errs
}

// parseOptionalTimeParam reads an optional RFC 3339 query parameter. Absent
// ⇒ zero time (the caller's own default applies). A malformed value writes
// 400 invalid_request and returns ok=false — shared by every compliance
// report handler that accepts a "since" filter.
func parseOptionalTimeParam(ctx core.HandlerContext, name string) (time.Time, bool) {
	v := ctx.Query(name)
	if v == "" {
		return time.Time{}, true
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return time.Time{}, false
	}
	return t.UTC(), true
}

// HandleAdminSOC2Report serves GET /api/v1/admin/compliance/soc2-evidence —
// the aggregated evidence pack for common SOC2 controls. admin:read gating is
// the caller's responsibility (the /api/v1/admin/ prefix middleware). Query
// parameters: since (RFC 3339, optional; default DefaultSOC2Window).
func HandleAdminSOC2Report(r *SOC2Reporter, log spi.Logger, ctx core.HandlerContext) {
	since, ok := parseOptionalTimeParam(ctx, "since")
	if !ok {
		return
	}
	ev, err := r.Generate(ctx.Request().Context(), SOC2Options{Since: since})
	if err != nil {
		// Best-effort: still 200 with the partial pack (ev.Errors already
		// carries the detail for the caller); log for operator visibility.
		log.Error("soc2 evidence generation had section errors", "error", err)
	}
	ctx.JSON(http.StatusOK, ev)
}
