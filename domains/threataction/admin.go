package threataction

import (
	"encoding/json"
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Query parameter and response key constants for the threat-policy admin API.
//
// paramPolicyName is the route-param KEY passed to ctx.Param, not a route
// pattern segment: StdRouter's extractParams (shared/core/router.go) strips
// the leading ":" from a pattern segment like ":name" before storing it in
// the params map, so the lookup key here must be the bare "name" -- exactly
// how every sibling admin handler does it (e.g. interfaces/admin/connections.go
// uses ctx.Param("id"), not ctx.Param(":id")). A colon-prefixed key here would
// silently never match, making name always resolve to "" regardless of the
// URL's actual :name segment.
const (
	paramPolicyName = "name"

	keyPolicies = "policies"
	keyPolicy   = "policy"
	keyTotal    = "total"
)

// HandleAdminListPolicies serves GET /api/v1/admin/threat-policies — lists
// every configured threat policy. Admin-gated (admin:read) by the caller.
func HandleAdminListPolicies(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	policies, err := store.List(ctx.Request().Context())
	if err != nil {
		log.Error("threat policy list failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if policies == nil {
		policies = []ThreatPolicy{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		keyPolicies:    policies,
		keyTotal:       len(policies),
	})
}

// HandleAdminGetPolicy serves GET /api/v1/admin/threat-policies/:name —
// returns a single policy. Admin-gated (admin:read) by the caller.
func HandleAdminGetPolicy(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	name := ctx.Param(paramPolicyName)
	policy, err := store.Get(ctx.Request().Context(), name)
	if err != nil {
		if err == ErrPolicyNotFound {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		log.Error("threat policy get failed", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		keyPolicy:      policy,
	})
}

// HandleAdminPutPolicy serves PUT /api/v1/admin/threat-policies/:name —
// creates or updates a threat policy. Admin-gated (admin:write) by the caller.
//
// A decode failure (malformed JSON) is the generic ErrInvalidRequest, mirroring
// every other admin handler in this repo (e.g. interfaces/sso's handleSetDRMode).
// A semantically invalid but well-formed policy (unknown action, negative
// rate limit, bad condition operator) is the more specific ErrInvalidPolicy
// PLUS an error_description reason -- mirroring the same decode-vs-semantic
// split interfaces/admin/governance.go's HandleAdminProposeChange already
// uses (ErrInvalidRequest for a bad body, ErrChange* sentinels for a
// well-formed-but-invalid one). Without this, an unknown Action, a negative
// RateLimit.Max, or a bogus Conditions.Operator were previously stored
// as-is and only ever surfaced later as a swallowed "no handler
// registered" no-op at execution time (registry.go's Execute) -- never as
// feedback to the admin who set it.
func HandleAdminPutPolicy(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	name := ctx.Param(paramPolicyName)
	var policy ThreatPolicy
	if err := json.NewDecoder(ctx.Request().Body).Decode(&policy); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	policy.Name = name
	if reason := invalidPolicyReason(policy); reason != "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(core.ErrInvalidPolicy, reason))
		return
	}
	if err := store.Put(ctx.Request().Context(), policy); err != nil {
		log.Error("threat policy put failed", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
		keyPolicy:      policy,
	})
}

// invalidPolicyReason checks semantic constraints on an admin-submitted
// policy that JSON decoding alone cannot catch. Returns "" when policy is
// valid, else a human-readable reason suitable for error_description.
func invalidPolicyReason(policy ThreatPolicy) string {
	if !validAction(policy.Action) {
		return "action must be one of: noop, suspend, revoke, step_up_mfa, notify, challenge"
	}
	if reason := invalidRateLimitReason(policy.RateLimit); reason != "" {
		return reason
	}
	if policy.Conditions.Key != "" && !validOperator(policy.Conditions.Operator) {
		return `conditions.operator must be one of: "", "eq", "gt", "lt", "exists"`
	}
	return ""
}

// validAction reports whether a is a known Action constant. Empty is
// accepted, NOT rejected: registry.go's composite executor Execute treats
// act == "" identically to the explicit ActionNoop (same branch, same
// "policy action is noop" result), so an admin who omits action gets the
// same well-defined no-op behavior as a YAML-seeded catch-all/observation
// policy -- rejecting it here would contradict how the runtime already
// treats it as a meaningful, intentional value, not a mistake.
func validAction(a Action) bool {
	switch a {
	case "", ActionNoop, ActionSuspend, ActionRevoke, ActionStepUpMFA, ActionNotify, ActionChallenge:
		return true
	default:
		return false
	}
}

// invalidRateLimitReason applies the "<=0 disables" idiom registry.go's
// allow() already uses at evaluation time (rl.Max <= 0 || rl.PerWindow.Duration
// <= 0 -> unlimited, i.e. no rate limiting): 0 is a legitimate, intentional
// "off" value, so only a genuinely negative Max or PerWindow -- which can
// only be a mistake, never a deliberate setting -- is rejected up front.
func invalidRateLimitReason(rl *RateLimitPolicy) string {
	if rl == nil {
		return ""
	}
	if rl.Max < 0 {
		return "rate_limit.max must not be negative"
	}
	if rl.PerWindow.Duration < 0 {
		return "rate_limit.per_window must not be negative"
	}
	return ""
}

// validOperator reports whether op is a known Conditions.Operator value.
// Only checked by invalidPolicyReason when Conditions.Key is set --  an
// empty Key is already "unconditional" per ThreatConditions.Match, so an
// Operator alongside it is inert and not worth rejecting.
func validOperator(op string) bool {
	switch op {
	case "", "eq", "gt", "lt", "exists":
		return true
	default:
		return false
	}
}

// HandleAdminDeletePolicy serves DELETE /api/v1/admin/threat-policies/:name —
// deletes a threat policy. Admin-gated (admin:write) by the caller.
func HandleAdminDeletePolicy(store ThreatPolicyStore, log spi.Logger, ctx core.HandlerContext) {
	name := ctx.Param(paramPolicyName)
	if err := store.Delete(ctx.Request().Context(), name); err != nil {
		if err == ErrPolicyNotFound {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		log.Error("threat policy delete failed", "name", name, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus: core.StatusOK,
	})
}
