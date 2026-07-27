package middleware

import "github.com/yangwb1123/snaplink/shared/core"

// TokenNoStoreHeaders stamps RFC 6749 §5.1's "credentialed-response"
// cache headers on the response:
//
//	Cache-Control: no-store
//	Pragma:        no-cache
//
// /token, /token/introspect, /token/revoke[-all], /par, /auth/login,
// /userinfo, and /register* all credential out tokens or token-shaped
// state — caching ANY of them cross-user (an intermediary, an
// over-eager browser, a CDN) is catastrophic. Same rule applies to
// error responses on these endpoints: a cached 401 from /userinfo
// keyed only on URL would serve the wrong user.
//
// Pragma: no-cache is the HTTP/1.0 companion the RFC requires
// alongside Cache-Control; both go on every response regardless of
// status so error bodies (which include error_code shapes a snooping
// cache could fingerprint) get the same treatment as success.
func TokenNoStoreHeaders(ctx core.HandlerContext) {
	h := ctx.ResponseWriter().Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

// ClearSiteData sets the Clear-Site-Data response header, instructing the
// browser to purge cache, cookies, and storage for this origin. Used on
// POST /logout and POST /me/account/erase — the two endpoints that represent
// a DEFINITIVE end to the user's session on this origin (unlike a single
// token revoke, which may leave other sessions/tabs on this origin alive).
// Callers gate this behind the security-headers feature flag
// (sso.Server.ClearSiteData); this function always sets the header when
// called, unconditionally.
func ClearSiteData(ctx core.HandlerContext) {
	ctx.ResponseWriter().Header().Set("Clear-Site-Data", `"cache", "cookies", "storage"`)
}
