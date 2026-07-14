package admin

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/tokenexchange"
	"github.com/snaplink/sso/domains/userlifecycle"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// User-lifecycle state-machine admin handlers. GET returns a user's current
// lifecycle state, the transitions legal from it, and the full transition
// history; POST requests a transition, validated against the legal-transition
// table (userlifecycle.ValidateTransition) and applied with optimistic
// concurrency. Every applied transition is audited (EventAdminUserLifecycleChanged)
// with the acting admin as ActorID. Both are gated UPSTREAM by AdminMiddleware
// (GET admin:read, POST admin:write) via the /api/v1/admin/ prefix.

// lifecycleTransitionRequest is the POST body: the target state plus an optional
// operator justification recorded in the transition history + audit event.
type lifecycleTransitionRequest struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// HandleAdminGetUserLifecycle serves GET /api/v1/admin/users/:id/lifecycle —
// the user's current lifecycle state, the states reachable from it in one legal
// move, and the append-only transition history. admin:read. A user unknown to
// the UserProvider is a 404; a user with no lifecycle record yet reports the
// implicit default (active) with empty history.
func HandleAdminGetUserLifecycle(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if u, err := d.UserProvider().GetByID(ctx.Request().Context(), userID); err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	rec, err := d.LifecycleStore().Get(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin get lifecycle failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if rec.History == nil {
		rec.History = []userlifecycle.Transition{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"user_id":             userID,
		"state":               rec.State,
		"allowed_transitions": userlifecycle.AllowedTransitions(rec.State),
		"history":             rec.History,
	})
}

// HandleAdminTransitionUserLifecycle serves POST /api/v1/admin/users/:id/lifecycle
// — request a lifecycle transition. admin:write. Body: {state, reason?}. An
// illegal transition is a 400 illegal_lifecycle_transition; an unrecognized
// target state is 400 unknown_lifecycle_state; a concurrent state change is 409
// lifecycle_state_conflict. On success emits admin_user_lifecycle_changed and
// returns the new state + the transitions now legal from it.
func HandleAdminTransitionUserLifecycle(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	var req lifecycleTransitionRequest
	if userID == "" || oauth.BindParams(ctx, &req) != nil || strings.TrimSpace(req.State) == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if u, err := d.UserProvider().GetByID(ctx.Request().Context(), userID); err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	rec, err := d.LifecycleStore().Get(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin lifecycle get failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	to := userlifecycle.State(strings.TrimSpace(req.State))
	if err := userlifecycle.ValidateTransition(rec.State, to); err != nil {
		writeLifecycleValidationError(ctx, err)
		return
	}
	applyLifecycleTransition(d, ctx, userID, rec.State, to, req.Reason)
}

// applyLifecycleTransition persists the validated transition and audits it,
// mapping a concurrency conflict to 409 and any other store error to 500. On
// success it responds 200 with the new state and the moves now legal from it.
func applyLifecycleTransition(d Deps, ctx core.HandlerContext, userID string, from, to userlifecycle.State, reason string) {
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	t := userlifecycle.NewTransition(from, to, strings.TrimSpace(reason), actor, time.Now().UTC())
	if err := d.LifecycleStore().Append(ctx.Request().Context(), userID, t); err != nil {
		if errors.Is(err, userlifecycle.ErrStateConflict) {
			ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrLifecycleStateConflict))
			return
		}
		d.Logger().Error("admin lifecycle append failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	userlifecycle.RecordTransition(ctx.Request().Context(), d.Auditor(), userID, t)
	ctx.JSON(http.StatusOK, map[string]any{
		"user_id":             userID,
		"state":               to,
		"previous_state":      from,
		"allowed_transitions": userlifecycle.AllowedTransitions(to),
	})
}

// writeLifecycleValidationError maps a ValidateTransition failure to its wire
// code: an unrecognized endpoint -> unknown_lifecycle_state, an illegal edge ->
// illegal_lifecycle_transition. Both are 400 (the caller is an authenticated
// admin, so neither is an enumeration oracle).
func writeLifecycleValidationError(ctx core.HandlerContext, err error) {
	switch {
	case errors.Is(err, userlifecycle.ErrUnknownState):
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrUnknownLifecycleState))
	default:
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrIllegalLifecycleTransition))
	}
}

// --- RFC 8693 token-exchange delegation-chain admin surface ---
//
// Unrelated to user-lifecycle above; appended to this file rather than its
// own (interfaces/admin is at its 10-file directory-fanout ceiling —
// directory_fanout_test.go — so a new file here would be a new violation)
// rather than touching token_portfolio.go, which has concurrent
// expiry-calendar work landing in parallel. A single read-only endpoint over
// the OPTIONAL tokenexchange.ChainStore (WithTokenExchangeChainStore); pure
// observability/governance, mirrors the read-only shape of
// token_portfolio.go's HandleSubjectTokens (individual params, not the
// broader admin.Deps interface, since this needs exactly one dependency).

// HandleTokenExchangeChain serves GET
// /api/v1/admin/tokenexchange/chains/:jti — the durable, recorded RFC 8693
// delegation-chain history for one minted access token's jti: every hop
// (actor, subject, client, chain depth, timestamp) a token-exchange grant
// recorded on its way to producing that token, oldest (root) first. Pure
// observability for audit / incident response — never consulted by any
// authorization decision, and does not affect token-exchange behavior.
// admin:read (default GET scope via AdminMiddleware's /api/v1/admin/ prefix
// — see token_portfolio.go's HandleSubjectTokens for the same convention).
//
// A nil store (should never reach this handler in production — the route is
// only mounted when one is wired, see interfaces/sso's
// mountAdminTokenExchangeChainRoutes) and an unrecorded/unknown jti both
// collapse to the SAME 404: from an operator's standpoint both mean
// "nothing recorded here", and there is no oracle concern gating an
// already-authenticated admin-only endpoint.
func HandleTokenExchangeChain(store tokenexchange.ChainStore, log spi.Logger, ctx core.HandlerContext) {
	jti := strings.TrimSpace(ctx.Param("jti"))
	if jti == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	chain, err := store.GetChain(ctx.Request().Context(), jti)
	if err != nil {
		log.Error("admin token-exchange chain lookup failed", "error", err, "jti", jti)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if len(chain) == 0 {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		"jti":          jti,
		"chain":        chain,
	})
}
