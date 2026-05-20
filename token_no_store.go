package sso

// tokenNoStoreHeaders stamps RFC 6749 §5.1 cache-prevention headers
// on credential-bearing responses. /token, /token/introspect,
// /token/revoke and /par all return data that intermediaries MUST
// NOT retain — leaked tokens replayed off a cache would defeat
// the rotation + revocation invariants the rest of the server
// enforces. Pragma: no-cache is the HTTP/1.0 companion the RFC
// requires alongside Cache-Control; both go on every response
// regardless of status so error bodies (which include error_code
// shapes a snooping cache could fingerprint) get the same
// treatment as success.
func tokenNoStoreHeaders(ctx HandlerContext) {
	h := ctx.ResponseWriter().Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
