package oauth

import (
	"github.com/yangwb1123/snaplink/shared/core"
)

// introspectSessionActive checks whether the session identified by claims.SID
// is still active. Oracle-safe: all failures (store error, not-found,
// expired, revoked) collapse to inactive so the caller returns
// {active:false} with no detail leak -- the same fail-closed contract
// MeshAuthorize's meshCheckSession (interfaces/sso/mesh_authz.go) applies to
// the identical signal. This matters in practice, not just in principle:
// every built-in SessionManager.Get (memory/redis/sqlite/postgres) already
// collapses missing, revoked, AND expired into core.ErrSessionNotFound --
// none of them return a populated Session with Revoked/expired fields set --
// so a fail-OPEN "err != nil -> active" would make the destroy/revoke path
// (the primary reason this check exists) a silent no-op. A nil
// SessionManager (unwired) skips the check entirely, same as a token with no
// sid.
func introspectSessionActive(d IntrospectDeps, ctx core.HandlerContext, claims *core.TokenClaims) bool {
	sm := d.SessionManager()
	if sm == nil {
		return true // unwired = skip check, same as no SID
	}
	sess, err := sm.Get(ctx.Request().Context(), claims.SID)
	if err != nil || sess == nil || sess.IsExpired() || sess.Revoked {
		return false
	}
	return true
}
