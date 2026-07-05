package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/platform/lifecycle/admingovernance"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// Admin governance framework: the generic change-approval workflow (HTTP
// handlers below, Deps-based like every other admin surface in this
// package) plus the transport-level write-quota / destructive-action-guard
// / IP-allowlist checks AdminMiddleware.HTTPMiddleware runs before a request
// ever reaches a handler. All four mechanisms are independently opt-in —
// see domains/admingovernance and docs/config-reference.md.

// ---------- Generic change-approval workflow (HTTP handlers) ----------

// proposeChangeRequest is the POST /api/v1/admin/changes body.
type proposeChangeRequest struct {
	ActionType string          `json:"action_type"`
	Payload    json.RawMessage `json:"payload"`
	Reason     string          `json:"reason"`
}

// changeID returns a random opaque change-request identifier, prefixed so
// it is visually distinguishable from other admin identifiers in logs and
// audit trails (mirrors break_glass.go's newBreakGlassID convention).
func changeID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "chg_" + hex.EncodeToString(b[:])
}

// HandleAdminProposeChange serves POST /api/v1/admin/changes — an admin
// proposes a governed mutation (action_type + payload); the record starts
// PENDING and requires a DIFFERENT admin's approval before an Applier (if
// registered for action_type) is invoked. admin:write. Reason is mandatory,
// mirroring break-glass's mandatory reason: an unexplained governed change
// is itself an audit finding.
func HandleAdminProposeChange(d Deps, ctx core.HandlerContext) {
	store := d.ApprovalStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	var req proposeChangeRequest
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	req.ActionType = strings.TrimSpace(req.ActionType)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.ActionType == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrChangeActionTypeRequired))
		return
	}
	if req.Reason == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrChangeReasonRequired))
		return
	}
	if !d.ApprovalActionTypes().Allows(req.ActionType) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrChangeActionTypeNotAllowed))
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	c := admingovernance.ChangeRequest{
		ID: changeID(), ActionType: req.ActionType, Payload: []byte(req.Payload),
		Reason: req.Reason, ProposedBy: actor, Status: admingovernance.ChangeStatusPending,
		CreatedAt: time.Now(),
	}
	rctx := ctx.Request().Context()
	c, err := store.Propose(rctx, c)
	if err != nil {
		d.Logger().Error("admin propose change failed", "action_type", req.ActionType, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordChangeEvent(d, rctx, audit.ClientIP(ctx.Request()), audit.EventAdminChangeProposed, c)
	ctx.JSON(http.StatusCreated, c)
}

// HandleAdminListChanges serves GET /api/v1/admin/changes — every
// pending/decided/applied change request, newest first. admin:read.
func HandleAdminListChanges(d Deps, ctx core.HandlerContext) {
	store := d.ApprovalStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	changes, err := store.List(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("admin list changes failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if changes == nil {
		changes = []admingovernance.ChangeRequest{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"changes": changes, "total": len(changes)})
}

// HandleAdminGetChange serves GET /api/v1/admin/changes/:id. admin:read. An
// unknown id is a 404 (the caller is an authenticated admin, not an
// enumeration surface).
func HandleAdminGetChange(d Deps, ctx core.HandlerContext) {
	store := d.ApprovalStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	c, err := store.Get(ctx.Request().Context(), id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	ctx.JSON(http.StatusOK, c)
}

// HandleAdminApproveChange serves POST /api/v1/admin/changes/:id/approve —
// a SECOND admin approves a pending change, immediately invoking the
// registered Applier (if any) for its action_type. admin:write. The
// approver MUST differ from the proposer (core.ErrChangeSelfApproval,
// enforced authoritatively in the store) — mirrors break-glass's two-person
// rule.
func HandleAdminApproveChange(d Deps, ctx core.HandlerContext) {
	store := d.ApprovalStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	approver, _, _ := ActorFromContext(rctx)
	c, err := admingovernance.ApproveAndApply(rctx, store, d.ChangeRegistry(), id, approver)
	if err != nil {
		writeChangeDecisionError(ctx, d, id, err)
		return
	}
	evtType := audit.EventAdminChangeApproved
	if c.Status == admingovernance.ChangeStatusFailed {
		evtType = audit.EventAdminChangeApplyFailed
	} else if c.Status == admingovernance.ChangeStatusApplied {
		evtType = audit.EventAdminChangeApplied
	}
	recordChangeEvent(d, rctx, audit.ClientIP(ctx.Request()), evtType, c)
	ctx.JSON(http.StatusOK, c)
}

// HandleAdminRejectChange serves POST /api/v1/admin/changes/:id/reject —
// any admin (including the proposer) rejects a pending change; it is never
// applied. admin:write.
func HandleAdminRejectChange(d Deps, ctx core.HandlerContext) {
	store := d.ApprovalStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	approver, _, _ := ActorFromContext(rctx)
	c, err := store.Reject(rctx, id, approver)
	if err != nil {
		writeChangeDecisionError(ctx, d, id, err)
		return
	}
	recordChangeEvent(d, rctx, audit.ClientIP(ctx.Request()), audit.EventAdminChangeRejected, c)
	ctx.JSON(http.StatusOK, c)
}

// writeChangeDecisionError maps an Approve/Reject failure to its HTTP
// response — split out to keep the callers under the complexity budget.
func writeChangeDecisionError(ctx core.HandlerContext, d Deps, id string, err error) {
	switch {
	case errors.Is(err, admingovernance.ErrChangeNotFound):
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
	case errors.Is(err, admingovernance.ErrChangeSelfApproval):
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrChangeSelfApproval))
	case errors.Is(err, admingovernance.ErrChangeNotPending):
		ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrChangeNotPending))
	default:
		d.Logger().Error("admin change decision failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	}
}

// recordChangeEvent emits evtType with the change-approval evidence chain
// every lifecycle event carries: change_id, action_type, proposed_by, and
// (once decided) approved_by. No-op when no Auditor is wired.
func recordChangeEvent(d Deps, rctx context.Context, actorIP string, evtType audit.EventType, c admingovernance.ChangeRequest) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{Type: evtType, Outcome: audit.OutcomeSuccess, ActorID: c.ProposedBy, ActorIP: actorIP}
	audit.SetMeta(evt, "change_id", c.ID)
	audit.SetMeta(evt, "action_type", c.ActionType)
	audit.SetMeta(evt, "proposed_by", c.ProposedBy)
	if c.ApprovedBy != "" {
		audit.SetMeta(evt, "approved_by", c.ApprovedBy)
	}
	aud.Record(rctx, evt)
}

// ---------- Transport-level governance checks (AdminMiddleware) ----------

// Wire error codes for the transport-level checks below. Defined here
// (rather than shared/core) because these run at the pre-routing
// http.Handler layer alongside the EXISTING admin_auth_not_configured /
// missing_token / forbidden / rate_limit_exceeded literals in middleware.go
// — that layer has no core.HandlerContext to hang a core.ErrorBody off, so
// it has always used small local literals; these three follow suit rather
// than introducing a second, inconsistent convention.
const (
	errAdminWriteQuotaExceeded    = "admin_write_quota_exceeded"
	errAdminIPDenied              = "admin_ip_denied"
	errDestructiveConfirmRequired = "destructive_confirmation_required"
)

// HeaderConfirm is the explicit confirmation parameter a caller must send
// (X-Confirm: true) to proceed with a mutation classified destructive by
// SetDestructiveActions. A header — not a JSON body field — because this
// gate runs BEFORE any handler parses a body, and must also cover the
// grpc-gateway-proxied admin services (tenant/client/user/token/permission
// CRUD), which never reach interfaces/admin's own body binding. Mirrors the
// {confirm: true} convention the bulk-revoke-by-user and self-service
// account-erase endpoints already use at the body level.
const HeaderConfirm = "X-Confirm"

// adminQuotaConfig bundles the write-quota store with its evaluated limit
// as ONE Middleware field (rather than four) to stay within middleware.go's
// maintainability budget.
type adminQuotaConfig struct {
	store  admingovernance.WriteQuotaStore
	limit  int
	window time.Duration
	keyBy  string
}

// adminIPPolicy bundles the IP-allowlist/geo-lock check with the
// geo.Provider composed for its country dimension — reused from
// platform/geo, NOT reimplemented (see domains/admingovernance.Allowed).
type adminIPPolicy struct {
	cfg admingovernance.IPAllowlistConfig
	geo geo.Provider
}

// SetWriteQuota opts this Middleware into the per-tenant/admin write-quota
// gate: WRITE methods (POST/PUT/PATCH/DELETE) under /api/v1/admin/ consume
// one unit of key's fixed-window budget (see admingovernance.QuotaKey);
// exceeding limit within window returns 429. limit<=0 or window<=0 disables
// the check (store is set but never consulted). Distinct from SetRateLimit
// above: a QUOTA is a bounded budget that resets wholesale at each window
// boundary, not a continuously-refilling token-bucket rate.
func (a *Middleware) SetWriteQuota(store admingovernance.WriteQuotaStore, limit int, window time.Duration, keyBy string) {
	a.quota = &adminQuotaConfig{store: store, limit: limit, window: window, keyBy: keyBy}
}

// SetIPAllowlist opts this Middleware into the IP-allowlist/geo-lock gate.
// provider may be nil when only cfg.Nets (CIDR) rules are configured — the
// Countries dimension then always fails closed if non-empty (see
// admingovernance.Allowed).
func (a *Middleware) SetIPAllowlist(cfg admingovernance.IPAllowlistConfig, provider geo.Provider) {
	a.ipPolicy = &adminIPPolicy{cfg: cfg, geo: provider}
}

// SetDestructiveActions opts this Middleware into the destructive-action
// confirmation guard: a request matching one of set's (method, path-prefix)
// rules is refused (409) unless it carries X-Confirm: true.
func (a *Middleware) SetDestructiveActions(set admingovernance.DestructiveSet) {
	a.destructive = set
}

// checkIPPolicy enforces the optional IP-allowlist/geo-lock. Runs BEFORE
// bearer validation so a disallowed network never reaches auth machinery
// (no oracle: the response is identical whether or not a valid token would
// have followed). Composes with the EXISTING geo enrichment SPI
// (geo.DefaultIPExtractor, geo.Provider) rather than reimplementing IP/geo
// resolution.
func checkIPPolicy(w http.ResponseWriter, r *http.Request, p *adminIPPolicy) bool {
	if p == nil {
		return true
	}
	ip := geo.DefaultIPExtractor(r)
	var info *geo.GeoInfo
	if p.geo != nil && ip != nil {
		info, _ = p.geo.Lookup(r.Context(), ip)
	}
	if admingovernance.Allowed(ip, info, p.cfg) {
		return true
	}
	http.Error(w, `{"error":"`+errAdminIPDenied+`"}`, http.StatusForbidden)
	return false
}

// checkDestructiveConfirm enforces the configured destructive-action set.
func checkDestructiveConfirm(w http.ResponseWriter, r *http.Request, set admingovernance.DestructiveSet) bool {
	if len(set) == 0 {
		return true
	}
	if _, ok := set.Match(r.Method, r.URL.Path); !ok {
		return true
	}
	if strings.EqualFold(r.Header.Get(HeaderConfirm), "true") {
		return true
	}
	http.Error(w, `{"error":"`+errDestructiveConfirmRequired+`"}`, http.StatusConflict)
	return false
}

// isAdminWriteMethod reports whether m is a mutating HTTP method — the
// write-quota gate only ever consumes budget for these; GET/HEAD/OPTIONS
// (admin:read) never touch it.
func isAdminWriteMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// checkWriteQuota enforces the configured per-tenant/admin write-op budget.
// actorID/tenantHint come from the already-validated bearer claims.
func checkWriteQuota(w http.ResponseWriter, r *http.Request, q *adminQuotaConfig, actorID, tenantHint string) bool {
	if q == nil || q.store == nil || !isAdminWriteMethod(r.Method) {
		return true
	}
	key := admingovernance.QuotaKey(q.keyBy, actorID, tenantHint)
	res, err := q.store.Consume(r.Context(), key, q.limit, q.window, time.Now())
	if err != nil || !res.Allowed {
		if !res.ResetAt.IsZero() {
			w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(res.ResetAt).Seconds())))
		}
		http.Error(w, `{"error":"`+errAdminWriteQuotaExceeded+`"}`, http.StatusTooManyRequests)
		return false
	}
	return true
}

// methodScopeForPath returns the longest-matching path-prefix override
// registered via SetMethodScope, if any — the HTTP-side counterpart of
// scopeForGRPC's exact-match lookup in middleware.go. methodScopes is empty
// unless a caller explicitly registers an override (no production wiring did
// before wasmauthz's admin:read-despite-POST route), so this is a byte-
// identical no-op for every path with no override — just like the other
// transport-level checks in this file. Longest-prefix-wins mirrors this
// SDK's other prefix-keyed overrides (see WithBodyLimitForPath,
// WithRouteDeprecation in interfaces/sso).
func (a *Middleware) methodScopeForPath(path string) (string, bool) {
	bestPrefix, bestScope := "", ""
	for prefix, scope := range a.methodScopes {
		if len(prefix) > len(bestPrefix) && strings.HasPrefix(path, prefix) {
			bestPrefix, bestScope = prefix, scope
		}
	}
	return bestScope, bestPrefix != ""
}

// tenantHintFromClaims extracts a best-effort tenant identifier from the
// validated bearer's Extra claims — the SAME map RFC 9068 extra claims ride
// in elsewhere in this SDK. Empty when the token carries none (a global
// admin token), in which case QuotaKey falls back to admin identity.
func tenantHintFromClaims(claims *core.TokenClaims) string {
	if claims == nil || claims.Extra == nil {
		return ""
	}
	return claims.Extra[core.KeyTenantID]
}
