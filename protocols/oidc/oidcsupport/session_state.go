package oidcsupport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
)

// sessionStateSaltBytes is the byte length of the random salt appended to
// every computed session_state. It need not be secret — OpenID Connect
// Session Management 1.0 §2 transmits it in the clear as the suffix after
// "." specifically so the check_session_iframe page can recompute the same
// hash without the OP persisting or looking anything up; 16 bytes (128
// bits) is ample entropy to keep two session_state values for the same
// (client, origin, browser state) from ever colliding.
const sessionStateSaltBytes = 16

// BuildSessionState computes the OpenID Connect Session Management 1.0 §2
// `session_state` value for one authentication response:
//
//	session_state = Base64url(SHA-256(client_id + " " + origin + " " + browser_state + " " + salt)) + "." + salt
//
// clientID is the requesting RP's client_id. origin is the RP's
// scheme://host (see OriginFromURL — derived from its redirect_uri, the
// only allowlist-validated RP URL available at the authentication
// response). browserState is an opaque value that changes whenever the
// End-User's login state at the OP changes; the SDK uses the freshly
// created SSO session id, so a login always produces a fresh value and a
// subsequent logout (which clears the matching cookie — see
// check_session_iframe.go) makes the browser-side recomputation diverge
// from whatever value an RP memoized.
//
// A fresh random salt is generated on every call, so two session_state
// values computed from the SAME inputs are still never equal — this is
// deliberate per spec: it keeps an observer from correlating a User across
// separate RPs purely from the wire value.
func BuildSessionState(clientID, origin, browserState string) (string, error) {
	salt := make([]byte, sessionStateSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	saltStr := base64.RawURLEncoding.EncodeToString(salt)
	return sessionStateHash(clientID, origin, browserState, saltStr) + "." + saltStr, nil
}

// sessionStateHash is the pure hash half of the algorithm, split out so
// tests can exercise it against fixed inputs (BuildSessionState's salt is
// randomly generated, so its output alone isn't comparable across calls).
// This MUST stay byte-for-byte identical to the check_session_iframe page's
// client-side SHA-256 computation (checkSessionIframeHTML in
// check_session_iframe.go) — the two sides recompute independently and are
// never told each other's inputs beyond what already travels on the wire.
func sessionStateHash(clientID, origin, browserState, salt string) string {
	sum := sha256.Sum256([]byte(clientID + " " + origin + " " + browserState + " " + salt))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// OriginFromURL returns the RFC 6454 origin (scheme://host[:port]) of
// rawURL, or "" when rawURL doesn't parse or carries no scheme/host. Used to
// derive the "origin" input to BuildSessionState from the RP's registered
// redirect_uri.
func OriginFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
