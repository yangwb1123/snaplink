package handler

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// IsUnknownTokenErr classifies an issuer's Revoke/Validate error as a
// benign "this issuer didn't own the token" outcome versus a real
// failure. The multi-issuer revoke fan-out asks EVERY registered issuer
// to revoke; the one that doesn't own the token returns a not-found
// shape that must be treated as a no-op, while any OTHER error (infra
// blip, store timeout) means the bearer may still work and operators
// MUST be alerted via partial_revoke_failure. Returning err != nil here
// (treating every error as "unknown") would silently swallow those
// infra failures and defeat the logout-everywhere promise — so the
// classification matches only the conventional not-found error shapes.
// nil reports true so a clean revoke is never miscounted as a failure.
func IsUnknownTokenErr(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	for _, needle := range []string{"not found", "unknown", "no such"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// JWSHeaderAlg extracts the `alg` from a compact-JWS bearer's JOSE
// header without verifying anything. Returns (alg, true) only for a
// well-formed three-segment token (exactly two dots) whose first
// segment decodes to JSON carrying a non-empty alg; ("", false)
// otherwise — opaque tokens, malformed input, or a header missing alg
// all report "no JWS alg" so the caller passes them through to the
// opaque/session issuers untouched. This is a fast pre-filter feeding
// the server-level alg allowlist gate, NOT the authoritative parse
// (each issuer re-parses and re-validates its own tokens).
func JWSHeaderAlg(token string) (string, bool) {
	first := strings.IndexByte(token, '.')
	if first <= 0 {
		return "", false
	}
	if strings.Count(token, ".") != 2 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[:first])
	if err != nil {
		return "", false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil || header.Alg == "" {
		return "", false
	}
	return header.Alg, true
}

// AlgAllowed reports whether alg appears in the allowlist.
func AlgAllowed(alg string, allow []string) bool {
	for _, a := range allow {
		if a == alg {
			return true
		}
	}
	return false
}
