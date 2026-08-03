package sso

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/admin"
	"github.com/yangwb1123/snaplink/internal/adminuser"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/protocols/selfservice"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

// Admin/helpdesk user-management handlers are thin wrappers delegating to the
// admin package's HandleAdminX free functions (*Server satisfies admin.Deps via
// accessor methods); the logic + audit live in admin/users.go. recordAdminUserAction
// stays here because the B2B org handlers (server_b2b_handlers.go) still use it.

func (s *Server) handleAdminListUserConsents(ctx HandlerContext) {
	admin.HandleAdminListUserConsents(s, ctx)
}
func (s *Server) handleAdminRevokeUserConsent(ctx HandlerContext) {
	admin.HandleAdminRevokeUserConsent(s, ctx)
}
func (s *Server) handleAdminListUserMFA(ctx HandlerContext) { admin.HandleAdminListUserMFA(s, ctx) }
func (s *Server) handleAdminRemoveUserMFA(ctx HandlerContext) {
	admin.HandleAdminRemoveUserMFA(s, ctx)
}
func (s *Server) handleAdminResetUserPassword(ctx HandlerContext) {
	admin.HandleAdminResetUserPassword(s, ctx)
}
func (s *Server) handleAdminSetUserEmail(ctx HandlerContext) {
	admin.HandleAdminSetUserEmail(s, ctx)
}
func (s *Server) handleAdminClearAccountLockout(ctx HandlerContext) {
	admin.HandleAdminClearAccountLockout(s, ctx)
}
func (s *Server) handleAdminResetUserRecoveryCodes(ctx HandlerContext) {
	admin.HandleAdminResetUserRecoveryCodes(s, ctx)
}
func (s *Server) handleAdminRevokeUserDeviceSecrets(ctx HandlerContext) {
	admin.HandleAdminRevokeUserDeviceSecrets(s, ctx)
}
func (s *Server) handleAdminRevokeUserRefreshTokens(ctx HandlerContext) {
	admin.HandleAdminRevokeUserRefreshTokens(s, ctx)
}
func (s *Server) handleAdminRevokeUserPasswordResetTokens(ctx HandlerContext) {
	admin.HandleAdminRevokeUserPasswordResetTokens(s, ctx)
}
func (s *Server) handleAdminRevokeUserEmailChangeTokens(ctx HandlerContext) {
	admin.HandleAdminRevokeUserEmailChangeTokens(s, ctx)
}
func (s *Server) handleAdminListUserPasswordResetTokens(ctx HandlerContext) {
	admin.HandleAdminListUserPasswordResetTokens(s, ctx)
}
func (s *Server) handleAdminListUserEmailChangeTokens(ctx HandlerContext) {
	admin.HandleAdminListUserEmailChangeTokens(s, ctx)
}

// Admin user CRUD — thin wrappers delegating to internal/adminuser/handlers.go.
// The business logic + HTTP handlers live there (not in interfaces/admin/) to
// keep the admin directory within its per-directory go-file fanout budget.
func (s *Server) handleAdminCreateUser(ctx HandlerContext) {
	adminuser.HandleAdminCreateUser(s, ctx)
}
func (s *Server) handleAdminGetUser(ctx HandlerContext) {
	adminuser.HandleAdminGetUser(s, ctx)
}
func (s *Server) handleAdminUpdateUser(ctx HandlerContext) {
	adminuser.HandleAdminUpdateUser(s, ctx)
}
func (s *Server) handleAdminDeleteUser(ctx HandlerContext) {
	adminuser.HandleAdminDeleteUser(s, ctx)
}
func (s *Server) handleAdminListUsers(ctx HandlerContext) {
	adminuser.HandleAdminListUsers(s, ctx)
}

// User-lifecycle state machine (admin) — thin wrappers; the state-machine +
// validation live in domains/userlifecycle, the handlers in admin/lifecycle.go.
func (s *Server) handleAdminGetUserLifecycle(ctx HandlerContext) {
	admin.HandleAdminGetUserLifecycle(s, ctx)
}
func (s *Server) handleAdminTransitionUserLifecycle(ctx HandlerContext) {
	admin.HandleAdminTransitionUserLifecycle(s, ctx)
}

// handleAdminListAccessPolicies (zero-trust CAP governance view) moved to
// server_federation.go — this file was at the line budget.

// B2B org-management handlers — thin wrappers. The enterprise-connection,
// tenant-membership, and invitation admin logic lives in admin/{connections,tenants}.go;
// the self-service /me organization endpoints in selfservice/organizations.go.

// Enterprise connections (admin).
func (s *Server) handleAdminListConnections(ctx HandlerContext) {
	admin.HandleAdminListConnections(s, ctx)
}
func (s *Server) handleAdminGetConnection(ctx HandlerContext) { admin.HandleAdminGetConnection(s, ctx) }
func (s *Server) handleAdminUpsertConnection(ctx HandlerContext) {
	admin.HandleAdminUpsertConnection(s, ctx)
}
func (s *Server) handleAdminDeleteConnection(ctx HandlerContext) {
	admin.HandleAdminDeleteConnection(s, ctx)
}

// handleAdminListConnectionDomains / handleAdminVerifyConnectionDomain moved
// to server_federation.go (which already handles connectionStore-backed
// home-realm discovery) — this file was at the line budget.
func (s *Server) handleAdminGetConnectionHealth(ctx HandlerContext) {
	admin.HandleAdminGetConnectionHealth(s, ctx)
}
func (s *Server) handleAdminProbeConnection(ctx HandlerContext) {
	admin.HandleAdminProbeConnection(s, ctx)
}

// Tenant membership (admin).
func (s *Server) handleAdminListTenantMembers(ctx HandlerContext) {
	admin.HandleAdminListTenantMembers(s, ctx)
}
func (s *Server) handleAdminPutTenantMember(ctx HandlerContext) {
	admin.HandleAdminPutTenantMember(s, ctx)
}
func (s *Server) handleAdminRemoveTenantMember(ctx HandlerContext) {
	admin.HandleAdminRemoveTenantMember(s, ctx)
}
func (s *Server) handleAdminExportTenant(ctx HandlerContext) { admin.HandleAdminExportTenant(s, ctx) }

// Invitations (admin).
func (s *Server) handleAdminSendInvitation(ctx HandlerContext) {
	admin.HandleAdminSendInvitation(s, ctx)
}
func (s *Server) handleAdminListInvitations(ctx HandlerContext) {
	admin.HandleAdminListInvitations(s, ctx)
}
func (s *Server) handleAdminRevokeInvitation(ctx HandlerContext) {
	admin.HandleAdminRevokeInvitation(s, ctx)
}

// Self-service organization endpoints (/me).
func (s *Server) handleMyOrganizations(ctx HandlerContext) {
	selfservice.HandleMyOrganizations(s, ctx)
}
func (s *Server) handleLeaveMyOrganization(ctx HandlerContext) {
	selfservice.HandleLeaveMyOrganization(s, ctx)
}
func (s *Server) handleAcceptInvitation(ctx HandlerContext) {
	selfservice.HandleAcceptInvitation(s, ctx)
}

// Delegated org-admin self-service endpoint wrappers moved to
// sso_selfservice.go (beside mountOrgAdminSelfService) — this file was at
// the line budget.

// handleAdminListSessions returns all active sessions (delegates to
// SessionManager.ListAll). Gated by admin:read scope via the admin
// middleware. Mounted only when a SessionManager is wired.
func (s *Server) handleAdminListSessions(ctx HandlerContext) {
	if s.sessionMgr == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
		return
	}
	sessions, err := s.sessionMgr.ListAll(ctx.Request().Context())
	if err != nil {
		s.logger.Error("admin list sessions failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []*Session{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:  StatusOK,
		"sessions": sessions,
		"total":    len(sessions),
	})
}

// handleAdminLinkedSessions serves GET /api/v1/admin/sessions/linked/:subject
// (Cross-protocol Session Hub backlog item): every session, every protocol
// (core + SAML today), grouped by global_sid, for one subject. s.sessionHub
// is never nil (constructed unconditionally in NewServer — see sso.go), so
// unlike handleAdminListSessions above this needs no nil-store guard.
func (s *Server) handleAdminLinkedSessions(ctx HandlerContext) {
	admin.HandleLinkedSessions(s.SessionHub(), s.logger, ctx)
}

// handleAdminListTokens returns the active admin bearer tokens.
func (s *Server) handleAdminListTokens(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
		return
	}
	// Optional query param ?admin_id= to filter by issuing admin.
	adminID := ctx.Query("admin_id")
	tokens, err := s.adminTokenStore.List(ctx.Request().Context(), adminID)
	if err != nil {
		s.logger.Error("admin list tokens failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"tokens":  tokens,
	})
}

// handleAdminListCredentials returns the credential-rotation governance
// inventory: for every credential class registered with the
// platform/rotation Scheduler, its type, version, lifecycle status,
// created_at, and next rotation due. GOVERNANCE metadata only — the
// underlying rotation.Registry never held secret material, so there is
// nothing here to redact. Mounted only when WithCredentialRotation is wired.
func (s *Server) handleAdminListCredentials(ctx HandlerContext) {
	if s.credentialRegistry == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
		return
	}
	inventory := s.credentialRegistry.Inventory()
	if inventory == nil {
		inventory = []rotation.InventoryEntry{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:     StatusOK,
		"credentials": inventory,
	})
}

// The admin token-governance handlers (handleAdminTokenUsage,
// handleAdminTokenPolicies, handleAdminTokenPortfolio, handleAdminTokenSubject,
// handleAdminTokenSuspicious, handleAdminBulkRevoke, RunTokenAnomalyDetection)
// live in sso.go — relocated there to hold this file under the 500-line
// maintainability budget.

// handleAdminEndpoints serves GET /api/v1/admin/endpoints (admin:read via
// AdminMiddleware, same as every other /api/v1/admin/ route): the live
// route inventory for THIS replica, so an operator can answer "what is
// actually exposed" without cross-referencing config against source.
func (s *Server) handleAdminEndpoints(ctx HandlerContext) {
	live := make([]endpointInfo, 0, len(endpointCandidates()))
	for _, c := range endpointCandidates() {
		if c.on(s) {
			live = append(live, c.endpointInfo)
		}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:   StatusOK,
		"endpoints": live,
	})
}

// Compliance evidence-chain metadata keys every credential-compromise audit
// event carries: "who declared what leaked, when, and why", answerable from a
// single event without cross-referencing the rotation store.
const (
	metaKeyCredentialType       = "credential_type"
	metaKeyCredentialReason     = "credential_reason"
	metaKeyCredentialOldVersion = "credential_old_version"
	metaKeyCredentialNewVersion = "credential_new_version"
)

// compromiseCredentialRequest is the POST body: the mandatory operator reason.
type compromiseCredentialRequest struct {
	Reason string `json:"reason"`
}

// handleAdminCompromiseCredential serves POST
// /api/v1/admin/credentials/{type}/compromise (admin:write): an operator
// declares the credential class leaked, force-rotating it OFF schedule with NO
// overlap so the leaked version is retired from the verify set instantly. The
// response is the new version's GOVERNANCE metadata only — NEVER the secret.
// reason is mandatory: an unexplained compromise is itself an audit finding.
// Mounted only when WithCredentialCompromise is wired.
func (s *Server) handleAdminCompromiseCredential(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if s.credentialScheduler == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
		return
	}
	credType := corecredential.CredentialType(ctx.Param("type"))
	if credType == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	var req compromiseCredentialRequest
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrCompromiseReasonRequired))
		return
	}
	result, err := s.credentialScheduler.Compromise(ctx.Request().Context(), credType, reason)
	if err != nil {
		s.writeCompromiseError(ctx, credType, err)
		return
	}
	s.recordCredentialCompromise(ctx, credType, reason, result)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:    StatusOK,
		"credential": result.New,
	})
}

// writeCompromiseError maps a Scheduler.Compromise failure to its HTTP
// response. An unknown type is a 404 (the caller is an authorized admin, so
// this is not an enumeration oracle); a class whose rotator cannot instantly
// retire its secret is a 400; a mint failure is a 500 (the old credential
// keeps serving — the operator should retry).
func (s *Server) writeCompromiseError(ctx HandlerContext, credType corecredential.CredentialType, err error) {
	switch {
	case errors.Is(err, rotation.ErrUnknownCredentialType):
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
	case errors.Is(err, corecredential.ErrCompromiseUnsupported):
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrCredentialCompromiseUnsupported))
	default:
		s.logger.Error("credential compromise failed", "type", string(credType), "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
	}
}

// recordCredentialCompromise emits the admin_credential_compromised audit event
// with the compliance evidence chain. No-op when no Auditor is wired.
func (s *Server) recordCredentialCompromise(ctx HandlerContext, credType corecredential.CredentialType, reason string, result rotation.CompromiseResult) {
	if s.auditor == nil {
		return
	}
	actor, _, _ := admin.ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{
		Type:    audit.EventAdminCredentialCompromised,
		Outcome: audit.OutcomeSuccess,
		ActorID: actor,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, metaKeyCredentialType, string(credType))
	audit.SetMeta(evt, metaKeyCredentialReason, reason)
	audit.SetMeta(evt, metaKeyCredentialOldVersion, strconv.Itoa(result.Compromised.Version))
	audit.SetMeta(evt, metaKeyCredentialNewVersion, strconv.Itoa(result.New.Version))
	s.auditor.Record(ctx.Request().Context(), evt)
}

// handleAdminRevokeToken revokes a single admin bearer token by ID.
func (s *Server) handleAdminRevokeToken(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
		return
	}
	tokenID := ctx.Param("id")
	if tokenID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	if err := s.adminTokenStore.Revoke(ctx.Request().Context(), tokenID); err != nil {
		s.logger.Error("admin revoke token failed", "id", tokenID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	s.recordAdminTokenRevoked(ctx, tokenID)
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusOK})
}

// recordAdminTokenRevoked emits admin_token_revoked — previously never fired
// on this path, leaving zero forensic trail. No-op when no Auditor is wired.
func (s *Server) recordAdminTokenRevoked(ctx HandlerContext, tokenID string) {
	if s.auditor == nil {
		return
	}
	actor, _, _ := admin.ActorFromContext(ctx.Request().Context())
	s.auditor.Record(ctx.Request().Context(), &audit.Event{
		Type: audit.EventAdminTokenRevoked, Outcome: audit.OutcomeSuccess,
		ActorID: actor, ActorIP: audit.ClientIP(ctx.Request()), TokenID: tokenID,
	})
}

// Break-glass (emergency support) admin sessions — thin wrappers. The
// lifecycle logic (reason/TTL validation, impersonation-session minting,
// revocation cascade, audit metadata) lives in admin/break_glass.go.
func (s *Server) handleAdminCreateBreakGlass(ctx HandlerContext) {
	admin.HandleCreateBreakGlass(s, ctx)
}
func (s *Server) handleAdminListBreakGlass(ctx HandlerContext) {
	admin.HandleListBreakGlass(s, ctx)
}
func (s *Server) handleAdminRevokeBreakGlass(ctx HandlerContext) {
	admin.HandleRevokeBreakGlass(s, ctx)
}
func (s *Server) handleAdminApproveBreakGlass(ctx HandlerContext) {
	admin.HandleApproveBreakGlass(s, ctx)
}
func (s *Server) handleAdminImpersonateBreakGlass(ctx HandlerContext) {
	admin.HandleImpersonateBreakGlass(s, ctx)
}

// mountAdminBreakGlass registers the break-glass (emergency support) admin
// session lifecycle: create (bounded, audited on-behalf-of grant, reason
// mandatory), list pending+active, revoke (cascades derived-session
// destruction), approve (two-person rule — the approver must differ from the
// creator), and impersonate (mint a live target-user bearer for an
// active+approved impersonate/escalate grant, bounded by the grant TTL).
// Mounted only when a BreakGlassStore is wired — byte-identical without it.
// GET is admin:read; POST/DELETE are admin:write via the default
// AdminMiddleware method-scope rule. Relocated from server_routes_admin.go
// (which was at its line budget) to sit beside the handlers it wires.
func (s *Server) mountAdminBreakGlass(api Router) {
	if s.breakGlassStore == nil {
		return
	}
	api.POST(PathAdminBreakGlass, s.handleAdminCreateBreakGlass)
	api.GET(PathAdminBreakGlass, s.handleAdminListBreakGlass)
	api.DELETE(PathAdminBreakGlassByID, s.handleAdminRevokeBreakGlass)
	api.POST(PathAdminBreakGlassApprove, s.handleAdminApproveBreakGlass)
	api.POST(PathAdminBreakGlassImpersonate, s.handleAdminImpersonateBreakGlass)
}

// handleAdminLogout revokes the admin bearer token used in the current
// request. The token is validated and its jti (matching AdminToken.ID)
// is used to revoke it. On success the caller should discard the token.
func (s *Server) handleAdminLogout(ctx HandlerContext) {
	if s.adminTokenStore == nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrNotFound))
		return
	}
	token := bearerToken(ctx.Request())
	if token == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, core.ErrUnauthorized))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), token)
	if err != nil || !core.IsAccessTokenClaims(claims) {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, core.ErrInvalidToken))
		return
	}
	if claims.JTI == "" {
		s.logger.Error("admin logout: token has no jti")
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, core.ErrInvalidRequest))
		return
	}
	if err := s.adminTokenStore.Revoke(ctx.Request().Context(), claims.JTI); err != nil {
		s.logger.Error("admin logout revoke failed", "jti", claims.JTI, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, core.ErrInternal))
		return
	}
	s.recordAdminTokenRevoked(ctx, claims.JTI)
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: "logged_out"})
}

// handleAdminEventsStream implements GET /api/v1/admin/events/stream (see
// platform/sse). Mounted only when WithSSEBroker is wired; admin:read is
// enforced by the admin middleware via the /api/v1/admin/ prefix like every
// other handler in this file, not by this handler itself.
func (s *Server) handleAdminEventsStream(ctx HandlerContext) {
	sse.HandleStream(s.sseBroker, s.sseHeartbeat, ctx)
}

// RunBreakGlassSweeper wakes every interval and sweeps expired break-glass
// admin sessions: destroys their impersonation sessions and emits
// admin_break_glass_expired for each. This is the ACTIVE enforcement of "a
// break-glass grant's derived session/token becomes invalid immediately at
// expiry" — the lazy expiry applied on Get/List only flips the REPORTED
// status for a caller who happens to read the store; nothing else revokes
// the derived session until this sweep runs.
//
// Same shutdown contract as the other retention loops in
// cmd/sso-server/serverbuildstore (RunAuditRetention et al.): exits on ctx
// cancellation, a sweep error is logged but never tears down the loop, and
// it is the OPERATOR's responsibility to start it in a goroutine — it is not
// started automatically by NewServer/Mount, so embedding the SDK in tests or
// short-lived processes never leaks it.
//
//	go srv.RunBreakGlassSweeper(ctx, time.Minute)
//
// No-op when no BreakGlassStore is wired or interval <= 0.
func (s *Server) RunBreakGlassSweeper(ctx context.Context, interval time.Duration) {
	if s.breakGlassStore == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := admin.SweepBreakGlassOnce(s, ctx); err != nil {
				s.logger.Error("break-glass sweep failed", "error", err)
			}
		}
	}
}
