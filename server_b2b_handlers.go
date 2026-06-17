package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/core"
)

// B2B org-management handlers: enterprise connections (runtime CRUD),
// tenant membership (admin roster + self-service list/leave), and email
// invitations (send/list/accept). Split out of handlers_admin.go to keep
// each file focused on one domain. Same package; behavior-identical.

// connectionJSON is the wire shape for admin enterprise-connection management.
type connectionJSON struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name"`
	Domains     []string          `json:"domains"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config,omitempty"`
}

func connectionToJSON(c *connections.Connection) connectionJSON {
	return connectionJSON{
		ID: c.ID, TenantID: c.TenantID, Type: string(c.Type),
		DisplayName: c.DisplayName, Domains: c.Domains, Enabled: c.Enabled, Config: c.Config,
	}
}

// recordAdminConnectionAction emits a connection-mutation audit event keyed on
// the acting admin, with connection_id + tenant_id metadata.
func (s *Server) recordAdminConnectionAction(ctx HandlerContext, evtType audit.EventType, connID, tenantID string) {
	if s.auditor == nil {
		return
	}
	actor, _, _ := AdminActorFromContext(ctx.Request().Context())
	evt := &audit.Event{Type: evtType, Outcome: audit.OutcomeSuccess, ActorID: actor, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(evt, "connection_id", connID)
	audit.SetMeta(evt, KeyTenantID, tenantID)
	s.auditor.Record(ctx.Request().Context(), evt)
}

// handleAdminListConnections serves GET /api/v1/admin/connections?tenant_id=
// — lists a tenant's B2B enterprise connections. admin:read. tenant_id is
// required (the store indexes by tenant; there is no cross-tenant list).
func (s *Server) handleAdminListConnections(ctx HandlerContext) {
	tenantID := ctx.Request().URL.Query().Get(KeyTenantID)
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	conns, err := s.connectionStore.ByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		s.logger.Error("admin list connections failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	out := make([]connectionJSON, 0, len(conns))
	for _, c := range conns {
		out = append(out, connectionToJSON(c))
	}
	ctx.JSON(http.StatusOK, map[string]any{"connections": out})
}

// handleAdminGetConnection serves GET /api/v1/admin/connections/:id. admin:read.
// A missing connection is a 404.
func (s *Server) handleAdminGetConnection(ctx HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	c, err := s.connectionStore.Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, connections.ErrNoConnection) {
			ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
			return
		}
		s.logger.Error("admin get connection failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, connectionToJSON(c))
}

// handleAdminUpsertConnection serves POST /api/v1/admin/connections — create or
// replace a connection (and its domain routing). admin:write. Requires id +
// tenant_id; type must be oidc or saml. Emits admin_connection_upserted.
func (s *Server) handleAdminUpsertConnection(ctx HandlerContext) {
	var req connectionJSON
	if err := bindOAuthParams(ctx, &req); err != nil || req.ID == "" || req.TenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	ct := connections.ConnectionType(req.Type)
	if ct != connections.TypeOIDC && ct != connections.TypeSAML {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	conn := &connections.Connection{
		ID: req.ID, TenantID: req.TenantID, Type: ct,
		DisplayName: req.DisplayName, Domains: req.Domains, Enabled: req.Enabled, Config: req.Config,
	}
	if err := s.connectionStore.Upsert(ctx.Request().Context(), conn); err != nil {
		s.logger.Error("admin upsert connection failed", "id", req.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminConnectionAction(ctx, audit.EventAdminConnectionUpserted, req.ID, req.TenantID)
	ctx.JSON(http.StatusOK, connectionToJSON(conn))
}

// handleAdminDeleteConnection serves DELETE /api/v1/admin/connections/:id.
// admin:write. Idempotent (the store contract makes Delete a no-op on a missing
// id). Emits admin_connection_deleted.
func (s *Server) handleAdminDeleteConnection(ctx HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.connectionStore.Delete(ctx.Request().Context(), id); err != nil {
		s.logger.Error("admin delete connection failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminConnectionAction(ctx, audit.EventAdminConnectionDeleted, id, "")
	ctx.JSON(http.StatusNoContent, nil)
}

// membershipJSON is the wire shape for B2B org membership.
type membershipJSON struct {
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func membershipToJSON(m *core.TenantMembership) membershipJSON {
	return membershipJSON{TenantID: m.TenantID, UserID: m.UserID, Role: string(m.Role), CreatedAt: m.CreatedAt}
}

func validTenantRole(r core.TenantRole) bool {
	return r == core.TenantRoleMember || r == core.TenantRoleAdmin || r == core.TenantRoleGuest
}

// handleAdminListTenantMembers serves GET /api/v1/admin/tenants/:id/members —
// the org roster. admin:read.
func (s *Server) handleAdminListTenantMembers(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	members, err := s.tenantUserStore.ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		s.logger.Error("admin list tenant members failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	out := make([]membershipJSON, 0, len(members))
	for _, m := range members {
		out = append(out, membershipToJSON(m))
	}
	ctx.JSON(http.StatusOK, map[string]any{"members": out})
}

// handleAdminPutTenantMember serves PUT /api/v1/admin/tenants/:id/members/:user_id
// — add a user to an org or change their org role. admin:write. Body: {role}
// (member|admin|guest; defaults to member). Idempotent (upsert). Emits
// admin_tenant_member_added.
func (s *Server) handleAdminPutTenantMember(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	userID := ctx.Param("user_id")
	if tenantID == "" || userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Role string `json:"role"`
	}
	_ = bindOAuthParams(ctx, &req)
	role := core.TenantRole(req.Role)
	if role == "" {
		role = core.TenantRoleMember
	}
	if !validTenantRole(role) {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.tenantUserStore.Add(ctx.Request().Context(), &core.TenantMembership{
		TenantID: tenantID, UserID: userID, Role: role, CreatedAt: time.Now(),
	}); err != nil {
		s.logger.Error("admin add tenant member failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminTenantMemberAdded, userID, KeyTenantID, tenantID)
	ctx.JSON(http.StatusOK, map[string]any{"tenant_id": tenantID, "user_id": userID, "role": string(role)})
}

// handleAdminRemoveTenantMember serves DELETE /api/v1/admin/tenants/:id/members/:user_id
// — remove a user from an org. admin:write. Idempotent. Emits
// admin_tenant_member_removed.
func (s *Server) handleAdminRemoveTenantMember(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	userID := ctx.Param("user_id")
	if tenantID == "" || userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.tenantUserStore.Remove(ctx.Request().Context(), tenantID, userID); err != nil {
		s.logger.Error("admin remove tenant member failed", "tenant_id", tenantID, "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminTenantMemberRemoved, userID, KeyTenantID, tenantID)
	ctx.JSON(http.StatusNoContent, nil)
}

// handleMyOrganizations serves GET /me/organizations — the orgs the bearer
// subject belongs to. Credential-adjacent: no-store headers.
func (s *Server) handleMyOrganizations(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	members, err := s.tenantUserStore.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list my organizations failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	out := make([]membershipJSON, 0, len(members))
	for _, m := range members {
		out = append(out, membershipToJSON(m))
	}
	ctx.JSON(http.StatusOK, map[string]any{"organizations": out})
}

// handleLeaveMyOrganization serves DELETE /me/organizations/:tenant_id — the
// authenticated user leaves an org without admin intervention. Idempotent
// (leaving a non-member org succeeds). Emits org_left.
func (s *Server) handleLeaveMyOrganization(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	tenantID := ctx.Param("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.tenantUserStore.Remove(ctx.Request().Context(), tenantID, userID); err != nil {
		s.logger.Error("leave organization failed", "user_id", userID, "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if s.auditor != nil {
		evt := &audit.Event{Type: audit.EventOrgLeft, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		audit.SetMeta(evt, KeyTenantID, tenantID)
		s.auditor.Record(ctx.Request().Context(), evt)
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// invitationTTL bounds how long an org invitation token is valid.
const invitationTTL = 7 * 24 * time.Hour

// handleAdminSendInvitation serves POST /api/v1/admin/tenants/:id/invitations —
// mint + deliver a single-use org invitation. admin:write. Body: {email, role}
// (role member|admin|guest, default member). 501 when no InvitationSender is
// wired (the token must never be returned in the response). Emits
// invitation_sent (never the token/email). Returns 202.
func (s *Server) handleAdminSendInvitation(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	role := core.TenantRole(req.Role)
	if role == "" {
		role = core.TenantRoleMember
	}
	if !validTenantRole(role) {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if s.invitationSender == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	token := base64.RawURLEncoding.EncodeToString(b[:])
	rctx := ctx.Request().Context()
	if err := s.invitationStore.Issue(rctx, &core.Invitation{
		Token: token, TenantID: tenantID, Email: strings.TrimSpace(req.Email), Role: role,
		ExpiresAt: time.Now().Add(invitationTTL),
	}); err != nil {
		s.logger.Error("issue invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.invitationSender.SendInvitation(rctx, strings.TrimSpace(req.Email), tenantID, string(role), token); err != nil {
		s.logger.Error("send invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventInvitationSent, "", KeyTenantID, tenantID)
	ctx.JSON(http.StatusAccepted, map[string]any{"status": "sent"})
}

// handleAdminListInvitations serves GET /api/v1/admin/tenants/:id/invitations —
// pending org invitations. admin:read. NEVER returns the token value — only
// email + role + expiry.
func (s *Server) handleAdminListInvitations(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	invs, err := s.invitationStore.ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil {
		s.logger.Error("list invitations failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	out := make([]map[string]any, 0, len(invs))
	for _, inv := range invs {
		out = append(out, map[string]any{
			"email": inv.Email, "role": string(inv.Role),
			"expires_at": inv.ExpiresAt, "expired": inv.IsExpired(),
		})
	}
	ctx.JSON(http.StatusOK, map[string]any{"invitations": out})
}

// handleAcceptInvitation serves POST /me/invitations/accept — the authenticated
// subject redeems an invitation token and joins the invited org at the invited
// role. Body: {token}. Single-use (consumed). Oracle-safe: missing/expired/
// consumed token all collapse to one invitation_invalid. Emits
// invitation_accepted.
func (s *Server) handleAcceptInvitation(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvitationInvalid))
		return
	}
	rctx := ctx.Request().Context()
	inv, err := s.invitationStore.Consume(rctx, req.Token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvitationInvalid))
		return
	}
	if err := s.tenantUserStore.Add(rctx, &core.TenantMembership{
		TenantID: inv.TenantID, UserID: userID, Role: inv.Role, CreatedAt: time.Now(),
	}); err != nil {
		s.logger.Error("accept invitation: add membership failed", "tenant_id", inv.TenantID, "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if s.auditor != nil {
		evt := &audit.Event{Type: audit.EventInvitationAccepted, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		audit.SetMeta(evt, KeyTenantID, inv.TenantID)
		s.auditor.Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"tenant_id": inv.TenantID, "role": string(inv.Role)})
}
