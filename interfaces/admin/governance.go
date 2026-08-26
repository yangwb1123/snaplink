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

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/platform/lifecycle/admingovernance"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
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

// Wire error codes for the pre-routing transport checks. They remain local
// because this layer has no core.HandlerContext for core.ErrorBody.
const (
	errAdminWriteQuotaExceeded    = "admin_write_quota_exceeded"
	errAdminIPDenied              = "admin_ip_denied"
	errDestructiveConfirmRequired = "destructive_confirmation_required"
	errAdminRateLimitExceeded     = "rate_limit_exceeded"
)

func recordAdminDenial(rec *audit.Recorder, r *http.Request, typ audit.EventType, reason, actorID, tenantID string) {
	e := &audit.Event{Type: typ, Outcome: audit.OutcomeFailure, ActorID: actorID, TenantID: tenantID}
	if ip := geo.DefaultIPExtractor(r); ip != nil {
		e.ActorIP = ip.String()
	}
	audit.SetMeta(e, "method", r.Method)
	audit.SetMeta(e, "path", r.URL.Path)
	audit.SetMeta(e, "reason", reason)
	rec.Record(r.Context(), e)
}

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

// adminRateLimitKey is the constant bucket key checkRateLimit uses, so every
// admin request shares ONE bucket — preserving the "admin-wide" (not
// per-IP/per-admin) semantic the previous golang.org/x/time/rate.Limiter's
// single global bucket had, now that SetRateLimit is built on the shared,
// per-key ratelimit.Limiter abstraction.
const adminRateLimitKey = "admin"

// SetRateLimit sets a STATIC admin-wide rate limit (tokens/sec + burst),
// wrapped in a fresh, unshared PolicyStore. A convenience for callers that
// don't need SIGHUP hot-reload — see SetRateLimitPolicyStore for a store
// that can be swapped live.
func (a *Middleware) SetRateLimit(tokensPerSec float64, burst int) {
	a.rateLimitStore = ratelimit.NewPolicyStore(ratelimit.Policy{
		Default: ratelimit.NewMemoryLimiter(tokensPerSec, burst),
	})
}

// SetRateLimitPolicyStore wires a SHARED, hot-reloadable PolicyStore — the
// SAME abstraction interfaces/ratelimit's main request-chain middleware
// uses for security.rate_limit.* — so a config reload that rebuilds the
// wired limiter takes effect on the admin API too, without a restart.
// Previously the admin gate held its own standalone rate.Limiter with no
// connection to that hot-reload path at all. Only Policy.Default is
// consulted: the admin surface is gated as one bucket, not per-path.
func (a *Middleware) SetRateLimitPolicyStore(store *ratelimit.PolicyStore) {
	a.rateLimitStore = store
}

// checkRateLimit enforces the optional admin-wide rate limit set via
// SetRateLimit/SetRateLimitPolicyStore. nil store (neither ever called) is
// unlimited — byte-identical to a build without the feature.
func checkRateLimit(w http.ResponseWriter, r *http.Request, store *ratelimit.PolicyStore, rec *audit.Recorder) bool {
	if store == nil {
		return true
	}
	lim := store.Get().Default
	if lim == nil {
		return true
	}
	ok, retryAfter := lim.Allow(adminRateLimitKey)
	if ok {
		return true
	}
	// Ceiling division: RFC 7231 interprets Retry-After: 0 as "retry
	// immediately", so sub-second durations round up to 1.
	secs := int(retryAfter / time.Second)
	if retryAfter%time.Second > 0 {
		secs++
	}
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, `{"error":"`+errAdminRateLimitExceeded+`"}`, http.StatusTooManyRequests)
	recordAdminDenial(rec, r, audit.EventAdminRateLimited, errAdminRateLimitExceeded, "", "")
	return false
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
func checkIPPolicy(w http.ResponseWriter, r *http.Request, p *adminIPPolicy, rec *audit.Recorder) bool {
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
	recordAdminDenial(rec, r, audit.EventAdminIPDenied, errAdminIPDenied, "", "")
	return false
}

// checkDestructiveConfirm enforces the configured destructive-action set.
func checkDestructiveConfirm(w http.ResponseWriter, r *http.Request, set admingovernance.DestructiveSet, rec *audit.Recorder) bool {
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
	recordAdminDenial(rec, r, audit.EventAdminDestructiveConfirmRequired, errDestructiveConfirmRequired, "", "")
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
func checkWriteQuota(w http.ResponseWriter, r *http.Request, q *adminQuotaConfig, actorID, tenantHint string, rec *audit.Recorder) bool {
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
		recordAdminDenial(rec, r, audit.EventAdminWriteQuotaExceeded, errAdminWriteQuotaExceeded, actorID, tenantHint)
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
//
// A match requires a path-segment boundary right after prefix (path equals
// prefix, or the next byte is "/") — a bare strings.HasPrefix would let an
// unrelated future sibling route (e.g. registering ".../check" and later
// adding ".../checkpoint") silently inherit this override's scope instead
// of its own correct default.
func (a *Middleware) methodScopeForPath(path string) (string, bool) {
	bestPrefix, bestScope := "", ""
	for prefix, scope := range a.methodScopes {
		if len(prefix) <= len(bestPrefix) || !strings.HasPrefix(path, prefix) {
			continue
		}
		if len(path) != len(prefix) && path[len(prefix)] != '/' {
			continue
		}
		bestPrefix, bestScope = prefix, scope
	}
	return bestScope, bestPrefix != ""
}

// HandleAdminConvergeAccessPolicies runs the same bounded convergence pass as
// the periodic worker. POST is gated by admin:write before this handler.
type conditionalAccessConverger interface {
	RunConditionalAccessConvergence(context.Context) (conditionalaccess.ConvergenceSummary, error)
}

func HandleAdminConvergeAccessPolicies(d Deps, ctx core.HandlerContext) {
	converger, ok := d.(conditionalAccessConverger)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotSupported))
		return
	}
	summary, err := converger.RunConditionalAccessConvergence(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("conditional access convergence failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, summary)
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
