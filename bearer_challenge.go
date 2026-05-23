package sso

import "github.com/snaplink/sso/security"

import "strings"

// setBearerChallenge stamps an RFC 6750 §3 WWW-Authenticate header
// on a 401 response. Protected resources that accept Bearer tokens
// MUST include this challenge so RPs know which scheme to use and
// can branch on `error=invalid_token` to trigger a refresh vs.
// `error=insufficient_scope` (reserved for /userinfo scope gates
// added later).
//
// realm: the protection space — defaulted to "sso" when the
// issuer can't be resolved (handlers always have an issuer once
// the server is configured, but the empty fallback keeps the
// header well-formed in degenerate startup cases).
//
// errorCode / errorDescription: omitted for the "no credentials
// presented" case (RFC §3.1: error parameters are only included
// when the request had a token that failed validation).
//
// Description values are quoted-string escaped per RFC 7235 §2.2
// so untrusted upstream values (cert subject CN, future custom
// signals) can't break out and inject additional auth-params.
func setBearerChallenge(ctx HandlerContext, realm, errorCode, errorDescription string) {
	if realm == "" {
		realm = "sso"
	}
	parts := []string{`Bearer realm=` + security.QuoteAuthParam(realm)}
	if errorCode != "" {
		parts = append(parts, `error=`+security.QuoteAuthParam(errorCode))
	}
	if errorDescription != "" {
		parts = append(parts, `error_description=`+security.QuoteAuthParam(errorDescription))
	}
	ctx.ResponseWriter().Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
}
