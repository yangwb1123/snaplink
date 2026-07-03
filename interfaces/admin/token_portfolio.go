package admin

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// Token Portfolio admin surface (Phase 3 of token governance): the per-subject
// active-token view and the bulk-revoke workflow. Both reuse the EXISTING
// refresh-token revocation machinery (RefreshTokenSubjectIndex /
// RefreshTokenClientPurger / RefreshTokenSubjectCounter — the same SPIs
// /token/revoke-all and tenant suspension already use); nothing here builds a
// new revocation store. *sso.Server keeps thin wrappers delegating here.

// Revocation-storm protection caps for the bulk-revoke workflow. bulkRevokeSoftCap:
// a subject-scoped batch larger than this needs an explicit confirm=true.
// bulkRevokeHardCap: a batch larger than this is refused outright — the operator
// must narrow the scope. Both bound the blast radius of a single admin action
// so a fat-fingered or malicious bulk revoke can't wipe a whole deployment's
// refresh tokens in one call (the Edge-Cases "revocation storm" defense).
const (
	bulkRevokeSoftCap = 100
	bulkRevokeHardCap = 10000
)

// eventAdminTokensBulkRevoked is the governance audit event a completed bulk
// revoke emits. audit.EventType is an open string type (custom values are
// allowed), so it lives beside the handler that emits it.
const eventAdminTokensBulkRevoked audit.EventType = "admin_tokens_bulk_revoked"

const (
	metaKeyBulkRevokeSubject  = "subject"
	metaKeyBulkRevokeClientID = "client_id"
	metaKeyBulkRevokeCount    = "revoked_count"
)

// HandleSubjectTokens serves GET /api/v1/admin/tokens/subjects/:subject — the
// count of active refresh tokens a subject holds, read through the existing
// RefreshTokenSubjectCounter. Governance data only (a count, never token
// values). Optional ?client_id= scopes the count to one client. admin:read.
// When the wired refresh store cannot count (no RefreshTokenSubjectCounter),
// the response reports counted=false rather than erroring.
func HandleSubjectTokens(refresh oauth.RefreshTokenStore, log spi.Logger, ctx core.HandlerContext) {
	subject := strings.TrimSpace(ctx.Param("subject"))
	if subject == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	clientID := strings.TrimSpace(ctx.Query(core.KeyClientID))
	body := map[string]any{
		core.KeyStatus: core.StatusOK,
		"subject":      subject,
		"counted":      false,
	}
	if clientID != "" {
		body[core.KeyClientID] = clientID
	}
	counter, ok := refresh.(oauth.RefreshTokenSubjectCounter)
	if !ok {
		ctx.JSON(http.StatusOK, body)
		return
	}
	n, err := counter.CountForSubject(ctx.Request().Context(), subject, clientID)
	if err != nil {
		log.Error("admin subject token count failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	body["active_refresh_tokens"] = n
	body["counted"] = true
	ctx.JSON(http.StatusOK, body)
}

// bulkRevokeRequest is the POST /api/v1/admin/tokens/revoke body. At least one
// of Subject / ClientID MUST be set (both empty is rejected — never a
// wildcard-all). Confirm gates a large / un-previewable batch.
type bulkRevokeRequest struct {
	Subject  string `json:"subject"`
	ClientID string `json:"client_id"`
	Confirm  bool   `json:"confirm"`
}

// HandleBulkRevoke serves POST /api/v1/admin/tokens/revoke — the admin
// bulk-revoke workflow. It revokes a BOUNDED set of refresh tokens (all for a
// subject and/or a client) through the EXISTING RefreshTokenSubjectIndex /
// RefreshTokenClientPurger machinery — the same paths /token/revoke-all and
// tenant suspension use; it builds no new revocation store. Already-issued
// STATELESS access tokens aren't enumerable without their values, so they
// expire naturally (identical limitation to /token/revoke-all); refresh-token
// deletion is cluster-consistent because the refresh store is shared across
// replicas. admin:write.
func HandleBulkRevoke(refresh oauth.RefreshTokenStore, auditor *audit.Recorder, log spi.Logger, ctx core.HandlerContext) {
	if refresh == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrRefreshTokenNotConfigured))
		return
	}
	req, ok := parseBulkRevokeRequest(ctx)
	if !ok {
		return
	}
	deleted, errCode, status := executeBulkRevoke(refresh, ctx.Request().Context(), req)
	if errCode != "" {
		ctx.JSON(status, core.ErrorBody(errCode))
		return
	}
	recordBulkRevoke(auditor, ctx, req, deleted)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus:            core.StatusOK,
		metaKeyBulkRevokeCount:    deleted,
		metaKeyBulkRevokeSubject:  req.Subject,
		metaKeyBulkRevokeClientID: req.ClientID,
	})
}

// parseBulkRevokeRequest binds + validates the body. Writes the 400 and
// returns ok=false on a malformed body or an empty (subject AND client) scope.
func parseBulkRevokeRequest(ctx core.HandlerContext) (bulkRevokeRequest, bool) {
	var req bulkRevokeRequest
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return req, false
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.ClientID = strings.TrimSpace(req.ClientID)
	// Never a wildcard-all: a blank scope is a footgun, not "revoke
	// everything" (mirrors RefreshTokenClientPurger's empty-clientID guard).
	if req.Subject == "" && req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return req, false
	}
	return req, true
}

// executeBulkRevoke applies the bounded revoke after the storm-protection
// gate. Returns (deletedCount, errCode, httpStatus); errCode == "" on success.
func executeBulkRevoke(refresh oauth.RefreshTokenStore, rctx context.Context, req bulkRevokeRequest) (int, string, int) {
	if req.Subject != "" {
		return revokeForSubject(refresh, rctx, req)
	}
	return revokeForClient(refresh, rctx, req)
}

// revokeForSubject kills every refresh token a subject holds (optionally
// scoped to one client) via RefreshTokenSubjectIndex, gated by the caps.
func revokeForSubject(refresh oauth.RefreshTokenStore, rctx context.Context, req bulkRevokeRequest) (int, string, int) {
	idx, ok := refresh.(oauth.RefreshTokenSubjectIndex)
	if !ok {
		return 0, core.ErrRefreshTokenNotConfigured, http.StatusNotImplemented
	}
	if errCode, status, blocked := gateSubjectBatch(refresh, rctx, req); blocked {
		return 0, errCode, status
	}
	deleted, err := idx.DeleteAllForSubject(rctx, req.Subject, req.ClientID)
	if err != nil {
		return 0, core.ErrInternal, http.StatusInternalServerError
	}
	return deleted, "", 0
}

// gateSubjectBatch enforces the storm-protection caps for a subject-scoped
// revoke: pre-count via RefreshTokenSubjectCounter when available (refuse over
// the hard cap, require confirm over the soft cap); when the store cannot
// count, require confirm before a blind bulk delete. Returns blocked=true with
// the error to write when the request must not proceed.
func gateSubjectBatch(refresh oauth.RefreshTokenStore, rctx context.Context, req bulkRevokeRequest) (string, int, bool) {
	counter, ok := refresh.(oauth.RefreshTokenSubjectCounter)
	if !ok {
		if !req.Confirm {
			return core.ErrBulkRevokeConfirmationRequired, http.StatusConflict, true
		}
		return "", 0, false
	}
	n, err := counter.CountForSubject(rctx, req.Subject, req.ClientID)
	if err != nil {
		// Count failed — fall back to the confirm gate rather than blocking.
		if !req.Confirm {
			return core.ErrBulkRevokeConfirmationRequired, http.StatusConflict, true
		}
		return "", 0, false
	}
	if n > bulkRevokeHardCap {
		return core.ErrBulkRevokeBatchTooLarge, http.StatusConflict, true
	}
	if n > bulkRevokeSoftCap && !req.Confirm {
		return core.ErrBulkRevokeConfirmationRequired, http.StatusConflict, true
	}
	return "", 0, false
}

// revokeForClient kills every refresh token bound to one client via
// RefreshTokenClientPurger. A client-wide revoke can't be cheaply pre-counted,
// so it ALWAYS requires an explicit confirm — it is never a one-keystroke
// accident.
func revokeForClient(refresh oauth.RefreshTokenStore, rctx context.Context, req bulkRevokeRequest) (int, string, int) {
	purger, ok := refresh.(oauth.RefreshTokenClientPurger)
	if !ok {
		return 0, core.ErrRefreshTokenNotConfigured, http.StatusNotImplemented
	}
	if !req.Confirm {
		return 0, core.ErrBulkRevokeConfirmationRequired, http.StatusConflict
	}
	deleted, err := purger.DeleteAllForClient(rctx, req.ClientID)
	if err != nil {
		return 0, core.ErrInternal, http.StatusInternalServerError
	}
	return deleted, "", 0
}

// recordBulkRevoke emits the governance audit event for a completed bulk
// revoke: who revoked what scope, and how many refresh tokens fell. No-op when
// no auditor is wired.
func recordBulkRevoke(auditor *audit.Recorder, ctx core.HandlerContext, req bulkRevokeRequest, deleted int) {
	if auditor == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	e := &audit.Event{
		Type:    eventAdminTokensBulkRevoked,
		Outcome: audit.OutcomeSuccess,
		ActorID: actor,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	if req.Subject != "" {
		audit.SetMeta(e, metaKeyBulkRevokeSubject, req.Subject)
	}
	if req.ClientID != "" {
		audit.SetMeta(e, metaKeyBulkRevokeClientID, req.ClientID)
	}
	audit.SetMeta(e, metaKeyBulkRevokeCount, strconv.Itoa(deleted))
	auditor.Record(ctx.Request().Context(), e)
}
