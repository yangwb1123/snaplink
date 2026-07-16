package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// Break-glass (emergency support) admin sessions: a bounded, audited window
// in which AdminUserID may act on behalf of TargetUserID. SOC 2 CC6.1/CC6.2,
// PCI DSS 7.2, HIPAA §164.312(a) evidence chain. Extracted into the admin
// domain like every other management-plane surface; *sso.Server keeps thin
// wrappers delegating here. Gated by AdminMiddleware — GET admin:read,
// mutations admin:write (the default method-scope rule); no fine-grained
// per-action scope is introduced, matching every other admin endpoint.

// Metadata keys every break-glass lifecycle audit event carries — the SOC 2
// evidence chain an auditor walks to answer "who acted as whom, when, and
// why" from a single event, without cross-referencing the store.
const (
	metaKeyAdminID          = "admin_id"
	metaKeyTargetUserID     = "target_user_id"
	metaKeyAdminSessionID   = "admin_session_id"
	metaKeyBreakGlassReason = "break_glass_reason"
)

// createBreakGlassRequest is the POST /api/v1/admin/break-glass body.
type createBreakGlassRequest struct {
	TargetUserID    string `json:"target_user_id"`
	Reason          string `json:"reason"`
	Scope           string `json:"scope"`
	TTLSeconds      int    `json:"ttl_seconds"`
	RequireApproval bool   `json:"require_approval"`
	TenantID        string `json:"tenant_id"`
}

// HandleCreateBreakGlass serves POST /api/v1/admin/break-glass — a support
// admin requests a bounded, audited on-behalf-of grant for TargetUserID.
// admin:write. Reason is mandatory: an unexplained break-glass is itself an
// audit finding. TTL defaults to 15 minutes and is capped at 1 hour
// regardless of caller input. require_approval=true creates a PENDING grant
// a DIFFERENT admin must approve via POST .../approve before it can be used;
// otherwise the grant activates immediately, minting its impersonation
// session up front (impersonate/escalate scope only — readonly never mints
// one, so a readonly grant is structurally incapable of acting as the user).
func HandleCreateBreakGlass(d Deps, ctx core.HandlerContext) {
	store := d.BreakGlassStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	a, errCode, ok := newPendingBreakGlassSession(ctx)
	if !ok {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(errCode))
		return
	}
	// Privilege floor: an impersonate/escalate grant may NEVER target an admin —
	// checked here so the grant can't even be established (structural), and again
	// at the .../impersonate bearer mint (TOCTOU: target could gain admin later).
	// readonly grants only view, so they're exempt.
	if a.Scope != core.AdminScopeReadonly && refuseTargetPrivileged(d, ctx, a.AdminSession) {
		return
	}

	rctx := ctx.Request().Context()
	if !a.wasApprovalRequired {
		sids, err := mintImpersonationSession(d, rctx, a.AdminSession)
		if err != nil {
			d.Logger().Error("break-glass mint impersonation session failed", "target_user_id", a.TargetUserID, "error", err)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
		a.Status = core.AdminSessionActive
		a.ApprovedBy = a.AdminUserID
		a.SessionIDs = sids
	}
	a.AuditID = recordBreakGlassEvent(d, rctx, audit.ClientIP(ctx.Request()), audit.EventAdminBreakGlassCreated, a.AdminSession)
	if err := store.Create(rctx, a.AdminSession); err != nil {
		d.Logger().Error("break-glass create failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusCreated, a.AdminSession)
}

// pendingBreakGlassSession is a freshly validated (not yet minted/persisted)
// grant, plus whether the caller asked for the second-approval workflow —
// carried separately from core.AdminSession because "PENDING because
// approval was requested" and "PENDING transiently while HandleCreateBreakGlass
// decides" would otherwise be indistinguishable from Status alone.
type pendingBreakGlassSession struct {
	core.AdminSession
	wasApprovalRequired bool
}

// newPendingBreakGlassSession parses + validates a create request and builds
// the AdminSession skeleton (id/actor/reason/scope/TTL window), still
// Status=Pending regardless of require_approval — HandleCreateBreakGlass
// decides whether to activate it. Split out to keep the handler under the
// function-length budget.
func newPendingBreakGlassSession(ctx core.HandlerContext) (pendingBreakGlassSession, string, bool) {
	var req createBreakGlassRequest
	if err := oauth.BindParams(ctx, &req); err != nil {
		return pendingBreakGlassSession{}, core.ErrInvalidRequest, false
	}
	req.Reason = strings.TrimSpace(req.Reason)
	req.TargetUserID = strings.TrimSpace(req.TargetUserID)
	if req.Reason == "" {
		return pendingBreakGlassSession{}, core.ErrBreakGlassReasonRequired, false
	}
	if req.TargetUserID == "" {
		return pendingBreakGlassSession{}, core.ErrInvalidRequest, false
	}
	scope, ok := normalizeBreakGlassScope(req.Scope)
	if !ok {
		return pendingBreakGlassSession{}, core.ErrInvalidRequest, false
	}
	ttl := core.DefaultBreakGlassTTL
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	if ttl > core.MaxBreakGlassTTL {
		return pendingBreakGlassSession{}, core.ErrBreakGlassTTLExceeded, false
	}

	actor, _, _ := ActorFromContext(ctx.Request().Context())
	now := time.Now()
	return pendingBreakGlassSession{
		AdminSession: core.AdminSession{
			ID:           newBreakGlassID(),
			AdminUserID:  actor,
			TargetUserID: req.TargetUserID,
			TenantID:     req.TenantID,
			Reason:       req.Reason,
			Scope:        scope,
			Status:       core.AdminSessionPending,
			CreatedAt:    now,
			ExpiresAt:    now.Add(ttl),
		},
		wasApprovalRequired: req.RequireApproval,
	}, "", true
}

// HandleListBreakGlass serves GET /api/v1/admin/break-glass — lists pending
// + active grants (BreakGlassStore.List excludes revoked/expired, and
// lazily flips a past-TTL record to expired before filtering, so a stale
// grant never shows as actionable). admin:read.
func HandleListBreakGlass(d Deps, ctx core.HandlerContext) {
	store := d.BreakGlassStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	sessions, err := store.List(ctx.Request().Context())
	if err != nil {
		d.Logger().Error("break-glass list failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []core.AdminSession{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": sessions, "total": len(sessions)})
}

// HandleRevokeBreakGlass serves DELETE /api/v1/admin/break-glass/:id —
// revokes a grant and cascades destruction of every impersonation session
// minted under it, so a revoked grant can never be used again even though
// the underlying Session's own TTL hasn't lapsed yet. admin:write. Unknown
// id is a 404; revoking an already revoked/expired grant is idempotent.
func HandleRevokeBreakGlass(d Deps, ctx core.HandlerContext) {
	store := d.BreakGlassStore()
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
	a, err := store.Revoke(rctx, id)
	if err != nil {
		if errors.Is(err, core.ErrAdminSessionNotFound) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("break-glass revoke failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	cascadeRevokeSessions(d, rctx, a.SessionIDs)
	cascadeRevokeImpersonationTokens(d, rctx, a.ImpersonationTokens)
	recordBreakGlassEvent(d, rctx, audit.ClientIP(ctx.Request()), audit.EventAdminBreakGlassRevoked, a)
	ctx.JSON(http.StatusOK, map[string]string{core.KeyStatus: "revoked"})
}

// HandleApproveBreakGlass serves POST /api/v1/admin/break-glass/:id/approve
// — a SECOND admin approves a pending grant, minting its impersonation
// session (impersonate/escalate scope only) now that two-person control is
// satisfied. admin:write. The approver MUST differ from the grant's creator
// (core.ErrAdminSessionSelfApproval, enforced authoritatively in the store)
// — self-approval would defeat the entire point of a second reviewer.
func HandleApproveBreakGlass(d Deps, ctx core.HandlerContext) {
	store := d.BreakGlassStore()
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
	pending, err := store.Get(rctx, id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	approver, _, _ := ActorFromContext(rctx)
	// Mint BEFORE calling Approve so the sessionIDs can be handed to the
	// store atomically with the pending->active transition. If Approve then
	// rejects (self-approval, or the grant stopped being pending under us),
	// the freshly minted session is destroyed below — a rejected approval
	// must never leave a live impersonation session orphaned.
	sids, err := mintImpersonationSession(d, rctx, pending)
	if err != nil {
		d.Logger().Error("break-glass mint impersonation session failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	a, err := store.Approve(rctx, id, approver, sids)
	if err != nil {
		cascadeRevokeSessions(d, rctx, sids)
		writeApproveError(ctx, d, id, err)
		return
	}
	recordBreakGlassEvent(d, rctx, audit.ClientIP(ctx.Request()), audit.EventAdminBreakGlassApproved, a)
	ctx.JSON(http.StatusOK, a)
}

// writeApproveError maps a BreakGlassStore.Approve failure to its HTTP
// response. Split out of HandleApproveBreakGlass to keep that function
// under the complexity budget.
func writeApproveError(ctx core.HandlerContext, d Deps, id string, err error) {
	switch {
	case errors.Is(err, core.ErrAdminSessionNotFound):
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
	case errors.Is(err, core.ErrAdminSessionSelfApproval):
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrBreakGlassSelfApproval))
	case errors.Is(err, core.ErrAdminSessionNotPending):
		ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrBreakGlassNotPending))
	default:
		d.Logger().Error("break-glass approve failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	}
}

// SweepBreakGlassOnce performs one break-glass expiry pass: DeleteExpired
// returns every grant that was still pending/active past its TTL, and for
// each one this destroys its impersonation sessions and emits the expiry
// audit event. This — not the lazy expiry on Get/List, which only flips the
// REPORTED status — is what actually revokes a derived session at the
// window's close, independent of whether any admin ever reads the list
// again. Safe to call on an interval (see sso.Server.RunBreakGlassSweeper)
// or once from a test. No-op when no BreakGlassStore is wired.
//
// RunBreakGlassSweeper drives this from a PERMANENT background goroutine with
// no recover of its own (by design — see that method's doc comment), so every
// call here into a pluggable, operator-supplied implementation
// (BreakGlassStore, SessionManager, the token issuers RevokeToken fans out
// to, the Auditor Sink) is wrapped in recover(): an unrecovered panic in any
// one of them would otherwise crash the ENTIRE process — taking every
// in-flight request on every other endpoint down with it, not just break-glass
// handling. Mirrors tokenanomaly.Detector.processFindingSafe and
// domains/anomaly.Runner.inspectSafe, the same pattern for the other permanent
// sweeper loops in this codebase.
func SweepBreakGlassOnce(d Deps, ctx context.Context) (int, error) {
	store := d.BreakGlassStore()
	if store == nil {
		return 0, nil
	}
	expired, err := deleteExpiredSafe(ctx, store)
	if err != nil {
		return 0, err
	}
	for _, a := range expired {
		sweepExpiredGrantSafe(d, ctx, a)
	}
	return len(expired), nil
}

// deleteExpiredSafe wraps store.DeleteExpired in recover(). BreakGlassStore is
// a pluggable, operator-supplied implementation (core.BreakGlassStore) invoked
// from the permanent sweeper goroutine — a panic here surfaces as a sweep
// error (logged by the caller, retried next tick) instead of crashing the
// process.
func deleteExpiredSafe(ctx context.Context, store core.BreakGlassStore) (expired []core.AdminSession, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("break-glass DeleteExpired panic recovered: %v", r)
		}
	}()
	return store.DeleteExpired(ctx)
}

// sweepExpiredGrantSafe wraps one expired grant's revoke cascade in
// recover(): the SessionManager, the token issuers RevokeToken fans out to,
// and the Auditor Sink are all pluggable, operator-supplied implementations —
// a panic in any of them must drop only THIS grant's cascade, not escape the
// sweep loop and crash the permanent background goroutine an operator is
// documented to run RunBreakGlassSweeper from.
func sweepExpiredGrantSafe(d Deps, ctx context.Context, a core.AdminSession) {
	defer func() {
		if r := recover(); r != nil {
			d.Logger().Error("break-glass sweep cascade panic recovered", "panic", r, "id", a.ID)
		}
	}()
	cascadeRevokeSessions(d, ctx, a.SessionIDs)
	cascadeRevokeImpersonationTokens(d, ctx, a.ImpersonationTokens)
	recordBreakGlassEvent(d, ctx, "", audit.EventAdminBreakGlassExpired, a)
}

// normalizeBreakGlassScope validates the requested scope, defaulting an
// empty value to readonly — least privilege: a caller who doesn't ask for
// impersonate/escalate gets the scope that can never mint a session.
func normalizeBreakGlassScope(raw string) (core.AdminScope, bool) {
	switch core.AdminScope(raw) {
	case "":
		return core.AdminScopeReadonly, true
	case core.AdminScopeReadonly, core.AdminScopeImpersonate, core.AdminScopeEscalate:
		return core.AdminScope(raw), true
	default:
		return "", false
	}
}

// mintImpersonationSession creates the marked target-user session an
// impersonate/escalate grant uses as its bearer, via the wired
// SessionManager. AdminScopeReadonly NEVER mints one — a readonly grant has
// no session to use as a bearer, which is the structural (not merely
// policy-checked) guarantee that it cannot become a mutation path.
func mintImpersonationSession(d Deps, ctx context.Context, a core.AdminSession) ([]string, error) {
	if a.Scope == core.AdminScopeReadonly {
		return nil, nil
	}
	sm := d.SessionMgr()
	if sm == nil {
		return nil, nil
	}
	meta := core.SessionMeta{TenantID: a.TenantID, Kind: core.SessionKindAdminImpersonation}
	var (
		sess *core.Session
		err  error
	)
	if mc, ok := sm.(core.SessionMetaCreator); ok {
		sess, err = mc.CreateWithMeta(ctx, a.TargetUserID, meta)
	} else {
		sess, err = sm.Create(ctx, a.TargetUserID)
	}
	if err != nil {
		return nil, err
	}
	return []string{sess.ID}, nil
}

// cascadeRevokeSessions destroys every impersonation session minted under a
// break-glass grant, so a revoked/expired grant can never keep acting as the
// target user. Best-effort per session — a SessionManager that already
// forgot the id is not an error, so one bad id can't abort the rest of the
// cascade.
func cascadeRevokeSessions(d Deps, ctx context.Context, sessionIDs []string) {
	sm := d.SessionMgr()
	if sm == nil {
		return
	}
	for _, sid := range sessionIDs {
		_ = sm.Destroy(ctx, sid)
	}
}

// recordBreakGlassEvent emits evtType with the SOC 2 evidence-chain metadata
// every break-glass lifecycle event MUST carry, and returns the recorded
// event's ID (empty when no Auditor is wired) for AdminSession.AuditID.
// actorIP is passed in rather than derived from a HandlerContext because the
// background sweeper (SweepBreakGlassOnce) has no request to read it from.
func recordBreakGlassEvent(d Deps, rctx context.Context, actorIP string, evtType audit.EventType, a core.AdminSession) string {
	aud := d.Auditor()
	if aud == nil {
		return ""
	}
	evt := &audit.Event{
		Type:    evtType,
		Outcome: audit.OutcomeSuccess,
		ActorID: a.AdminUserID,
		ActorIP: actorIP,
	}
	audit.SetMeta(evt, metaKeyAdminID, a.AdminUserID)
	audit.SetMeta(evt, metaKeyTargetUserID, a.TargetUserID)
	audit.SetMeta(evt, metaKeyAdminSessionID, a.ID)
	audit.SetMeta(evt, metaKeyBreakGlassReason, a.Reason)
	aud.Record(rctx, evt)
	return evt.ID
}

// newBreakGlassID returns a random opaque break-glass session identifier.
// Prefixed so it's visually distinguishable from a user/session/client id in
// logs and audit trails.
func newBreakGlassID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "bg_" + hex.EncodeToString(b[:])
}
