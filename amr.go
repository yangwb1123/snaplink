package sso

import "slices"

// amrForResult returns the RFC 8176 Authentication Methods References for a
// completed authentication. Authenticators record the methods they actually
// used on AuthResult.AuthMethods (password -> ["pwd"], totp -> ["otp"],
// certificate -> ["x509"], ...); this surfaces those into the token's amr
// instead of collapsing the claim to the OAuth provider id. It falls back to
// the provider id only when an authenticator recorded nothing, so amr is
// never absent. The returned slice is a fresh copy — callers must not alias
// result.AuthMethods.
func amrForResult(result *AuthResult) []string {
	return amrOrProvider(result.AuthMethods, result.Provider)
}

// amrOrProvider returns methods when non-empty (a fresh copy), else the
// provider id as a single-element fallback so amr is never absent. Shared
// by the direct-login path (via amrForResult) and the authorization_code
// exchange (which replays the AuthMethods captured on the AuthCode).
func amrOrProvider(methods []string, provider string) []string {
	if len(methods) > 0 {
		return append([]string(nil), methods...)
	}
	return []string{provider}
}

// amrMultiFactor is RFC 8176 §2's "mfa" marker: more than one factor was used.
const amrMultiFactor = "mfa"

// mfaMethodAMR maps an MFA provider's method name to its RFC 8176 amr value
// where the two differ. Unmapped methods pass through so a custom provider
// still surfaces its own tag.
var mfaMethodAMR = map[string]string{
	"totp": "otp",
}

// withMFAMethod folds a verified second factor into an existing amr list: the
// factor's amr value plus the "mfa" multiple-factor marker, deduped and
// order-preserving. Used on the /auth/mfa second leg so the minted tokens
// carry the real multi-factor signal (e.g. ["pwd","otp","mfa"]) rather than
// only the first-factor method.
func withMFAMethod(existing []string, method string) []string {
	out := append([]string(nil), existing...)
	add := func(v string) {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if mapped, ok := mfaMethodAMR[method]; ok {
		add(mapped)
	} else {
		add(method)
	}
	add(amrMultiFactor)
	return out
}
