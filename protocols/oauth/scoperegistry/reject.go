package scoperegistry

import (
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Construction-error sentinels. All are fail-closed: a malformed registry
// (bare "*", misplaced wildcard, empty scope) fails boot loudly instead of
// silently widening the gate at runtime.
var (
	errFrozen       = errors.New("scoperegistry: registry is frozen after build")
	errEmptyScope   = errors.New("scoperegistry: scope must not be empty")
	errBareWildcard = errors.New(`scoperegistry: bare "*" is rejected — it would make the scope gate a no-op; use an exact scope or a "domain:*" wildcard`)
	errBadWildcard  = errors.New(`scoperegistry: wildcard must be a "domain:*" suffix (e.g. "admin:*"); any other "*" placement is rejected`)
)

// RejectUnregistered is the shared /token seam + per-branch helper: when the
// wired registry does not register one of the effective scopes, it writes the
// byte-identical plain invalid_scope body (core.ErrorBody, NO trace_id — the
// oracle-safety shape every existing grant-branch rejection emits) with
// status 400 and returns true so the caller returns immediately.
//
// A nil registry (unwired default) and an empty scope set are no-ops — the
// byte-compat baseline. Callers MUST invoke this on EFFECTIVE scopes
// (post-resolution, pre-issuance): the dispatch seam sees only request-borne
// scopes, while store-bound grants (authcode/device/CIBA/refresh families)
// mint scopes the request never carried.
func RejectUnregistered(ctx core.HandlerContext, reg Registry, scopes []string) bool {
	if reg == nil || len(scopes) == 0 {
		return false
	}
	for _, s := range scopes {
		if !reg.Registered(s) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
			return true
		}
	}
	return false
}

// FilterRegistered returns the input scopes minus any the registry does not
// register, preserving order (drops nothing when reg is nil). Used by the
// discovery snapshot so scopes_supported never advertises a scope /token
// would reject under an enabled registry; registry-off stays byte-identical.
func FilterRegistered(reg Registry, scopes []string) []string {
	if reg == nil || len(scopes) == 0 {
		return scopes
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if reg.Registered(s) {
			out = append(out, s)
		}
	}
	return out
}
