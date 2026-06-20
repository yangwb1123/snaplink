package oauth

import "net/http"

// BasicClientCreds extracts (client_id, client_secret) from an HTTP
// Basic Authorization header per RFC 6749 §2.3.1. Returns ok=false
// when absent or malformed. Wrapper exists to keep credential
// extraction syntactically uniform across /token, /token/introspect,
// /token/revoke, and /par — all of which honor Basic before body.
func BasicClientCreds(r *http.Request) (id, secret string, ok bool) {
	if r == nil {
		return "", "", false
	}
	u, p, basicOK := r.BasicAuth()
	if !basicOK {
		return "", "", false
	}
	return u, p, true
}
