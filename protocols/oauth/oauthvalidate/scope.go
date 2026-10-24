package oauthvalidate

import (
	"errors"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ErrScopeNotAllowed is returned by GrantedScopes when a requested scope
// is not in the client's (non-empty) AllowedScopes allowlist. Callers
// map it to the RFC 6749 §5.2 wire code core.ErrInvalidScope — a 400 on
// /token, or the RFC 9207 authz error body on /auth/login. It carries no
// detail about WHICH scope was rejected beyond the standard error, so it
// is not an enumeration oracle (SPAs branch on `error`, not the message).
var ErrScopeNotAllowed = errors.New("sso: requested scope not permitted for client")

// JoinScope joins a slice of scopes back into the space-delimited
// wire format used by the scope query parameter (RFC 6749 §3.3).
func JoinScope(scopes []string) string {
	return strings.Join(scopes, " ")
}

// SplitScope parses a space-delimited scope string into a slice,
// returning nil for empty input so the AuthCode / DeviceCode entry's
// Scopes field stays nil-not-empty (cleaner reflection / JSON marshal).
func SplitScope(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}

// GrantedScopes computes the scope an issued token actually carries,
// authorizing the requested set against the client's AllowedScopes
// allowlist (RFC 6749 §3.3). It is the single shared gate applied at
// every issuance entry (login / authorization_code capture, direct
// mint, client_credentials, device, CIBA, token-exchange) so the
// authorization decision is identical regardless of grant.
//
// Rules, each load-bearing:
//
//  1. openid is ALWAYS permitted. It is the OIDC trigger, not a
//     resource scope — discovery already advertises scopes_supported as
//     `openid ∪ AllowedScopes` (core.Client.scopesSupported), so the
//     enforcement here MUST match: a client may request openid even when
//     it isn't enumerated in AllowedScopes. openid is NOT auto-added
//     when the caller didn't request it (we never widen the grant).
//
//  2. Empty AllowedScopes ⇒ UNRESTRICTED. A client with no allowlist is
//     unconstrained and the requested set passes through verbatim — no
//     validation, no default. This keeps every pre-existing client
//     (which had no enforcement at all) byte-identical: the grant is
//     exactly what it would have been before this gate existed.
//
//  3. Non-empty AllowedScopes + non-empty request ⇒ every requested
//     scope (other than openid, rule 1) MUST appear in AllowedScopes. A
//     single out-of-allowlist scope REJECTS the whole request with
//     core.ErrInvalidScope rather than silently narrowing — silent
//     narrowing would hide a misconfigured client from its operator and
//     hand it a token weaker than it asked for without telling it. The
//     granted set is the (validated) requested set.
//
//  4. Non-empty AllowedScopes + EMPTY request ⇒ DEFAULT to a copy of
//     AllowedScopes MINUS openid and offline_access. Resource entitlements
//     remain defaulted, but the two protocol permissions require an explicit
//     request: openid opts into an ID token and offline_access authorizes a
//     refresh token. An allowlist ceiling alone is not offline authorization.
//
// The returned slice is order-preserving and de-duplicated; empties are
// trimmed. The caller passes the already-split request (oauth.SplitScope
// of the wire `scope` param). On rule-3 rejection it returns nil + the
// wire error; the caller maps it to a 400 invalid_scope (or, at the
// /auth/login authorization surface, to the authz error body with the
// RFC 9207 iss). The check is oracle-safe: invalid_scope is the standard
// RFC 6749 §5.2 error and MUST run AFTER client authentication so it
// never becomes a pre-auth probe.
func GrantedScopes(requested []string, client *core.Client) ([]string, error) {
	req := dedupeScopes(requested)

	// Rule 2: empty allowlist ⇒ unrestricted, byte-identical pass-through
	// (granted = requested as-is, including the empty case which yields
	// an empty grant exactly as before).
	if client == nil || len(client.AllowedScopes) == 0 {
		return req, nil
	}

	// Rule 4: nothing requested ⇒ default to the client's resource
	// entitlement. Explicit protocol permissions openid and offline_access
	// are excluded even when allowed: default resource scopes must not mint
	// an unrequested ID token or authorize unrequested offline credentials.
	if len(req) == 0 {
		def := make([]string, 0, len(client.AllowedScopes))
		for _, a := range client.AllowedScopes {
			if a == core.ScopeOpenID || a == core.ScopeOfflineAccess {
				continue
			}
			def = append(def, a)
		}
		return dedupeScopes(def), nil
	}

	allowed := make(map[string]struct{}, len(client.AllowedScopes))
	for _, a := range client.AllowedScopes {
		allowed[a] = struct{}{}
	}

	// Rule 3 (+ rule 1): validate every requested scope; openid and device_sso
	// bypass the allowlist as protocol triggers (OIDC / Native SSO 1.0), not
	// resource scopes.
	for _, s := range req {
		if s == core.ScopeOpenID || s == core.ScopeDeviceSSO {
			continue
		}
		if _, ok := allowed[s]; !ok {
			return nil, ErrScopeNotAllowed
		}
	}
	return req, nil
}

// dedupeScopes returns the input with empties trimmed and duplicates
// removed, preserving first-occurrence order. Shared by GrantedScopes so
// both the validated and defaulted paths emit a clean, stable set.
func dedupeScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
