package sso

import (
	"html/template"
	"net/http"

	"github.com/snaplink/sso/oidc"
)

// OIDC + RFC 9207 response-shaping helpers. Three concerns clustered
// here for navigability:
//
//   1. resolveIssuer + authzErrorBody* — RFC 9207 issuer-identification
//      stamping on every authorization-endpoint response.
//   2. renderFormPostResponse + helpers — OIDC Form Post Response Mode 1.0
//      auto-submit HTML for response_mode=form_post.
//   3. maybeSignUserInfo — OIDC userinfo signed-response (JWT) path.
//
// All three live on *Server because they reach into Server fields
// (issuer, idTokenIssuer, clientStore, logger).

// -----------------------------------------------------------------------------
// RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification.
//
// Defense against mix-up attacks: when a client is configured with
// multiple authorization servers, an attacker can attempt to trick the
// client into accepting an authorization response from one AS as if it
// came from another. Including the AS issuer identifier in every
// authorization response lets the client verify "this code/token came
// from the AS I expected" before redeeming the code at the token
// endpoint.
//
// RFC 9207 §2 is written for redirect-based responses (`?iss=...`
// query param on the redirect to the RP). This server's /auth/login is
// a BFF-shaped JSON endpoint rather than a 302-redirect endpoint; the
// adaptation is to include `iss` in the JSON response body alongside
// `code` / `state` / `error`. A client that builds the redirect URI
// on the SPA side can propagate the value into `iss=...` as the spec
// intends.

// resolveIssuer returns the issuer identifier this server stamps in
// authorization responses. Matches the value advertised in the OIDC
// discovery document: operator-configured `WithIssuer` value when set
// and not the default sentinel; otherwise the request's base URL.
//
// Critical invariant: the value returned here MUST equal
// `oidcConfiguration.Issuer` for the same request — RFC 9207 §2
// requires the `iss` parameter to be the same identifier the AS
// publishes via discovery, so a client comparing them detects mix-up.
func (s *Server) resolveIssuer(ctx HandlerContext) string {
	if s.issuer != "" && s.issuer != DefaultIssuer {
		return s.issuer
	}
	return requestBaseURL(ctx.Request())
}

// authzErrorBody returns the standard error envelope for an
// authorization endpoint response with `iss` stamped per RFC 9207 §2.
// Use this in handleLogin (and any future authorization endpoint) —
// NOT in token / userinfo / callback handlers, which are not
// authorization responses.
func (s *Server) authzErrorBody(ctx HandlerContext, code string) map[string]string {
	return map[string]string{
		KeyError: code,
		KeyIss:   s.resolveIssuer(ctx),
	}
}

// authzErrorBodyDesc is authzErrorBody plus an error_description.
func (s *Server) authzErrorBodyDesc(ctx HandlerContext, code, desc string) map[string]string {
	return map[string]string{
		KeyError:            code,
		KeyErrorDescription: desc,
		KeyIss:              s.resolveIssuer(ctx),
	}
}

// -----------------------------------------------------------------------------
// OpenID Connect Form Post Response Mode 1.0.
//
// The RP requests `response_mode=form_post` when it wants the
// authorization response delivered as an HTML auto-submitted POST
// to its redirect_uri, rather than the default query-string redirect.
// Useful for RPs that handle POST bodies more naturally than parsing
// fragment / query parameters, and for delivering longer responses
// (id_token, etc.) without URL-length limits.
//
// Spec: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
//
// This implementation:
//   - Renders a minimal HTML document with a hidden form whose body
//     POSTs {code, state, iss} to redirect_uri.
//   - Auto-submits via a body onload handler — operators using strict
//     CSP that blocks inline event handlers should serve this
//     endpoint outside their CSP middleware OR allowlist a 'self'
//     script-src for /auth/login.
//   - Provides a manual submit button inside <noscript> so RPs that
//     disable JS still see a fallback (the user clicks once).
//   - All response values pass through html/template's
//     auto-escaping (URL context for action=, attribute context for
//     value=), so an attacker can't break out of the form fields.
//   - Hardens response headers: X-Frame-Options: DENY (clickjacking)
//     + Cache-Control: no-store + Referrer-Policy: no-referrer
//     (don't leak the AS's URL to the RP via Referer; the auth
//     response itself is what the RP needs).

// ResponseModeFormPost is the OIDC Form Post Response Mode 1.0
// magic string for the `response_mode` parameter.
const ResponseModeFormPost = "form_post"

// ResponseModeQuery is the default response_mode for response_type=code
// per OIDC Core §3.1.2.5: parameters appended to the redirect_uri's
// query string.
const ResponseModeQuery = "query"

// ResponseModeFragment is the default response_mode for token-bearing
// response types (implicit flow). Parameters delivered after `#`.
const ResponseModeFragment = "fragment"

// formPostTemplate renders the auto-POST HTML page. The form
// elements are scoped via id="f" so the noscript fallback button's
// `form="f"` association keeps working even though the button
// itself lives outside the form (HTML5 spec).
var formPostTemplate = template.Must(template.New("formPost").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Submitting…</title>
</head>
<body onload="document.forms[0].submit()">
<noscript>
<p>JavaScript is required to complete sign-in. Please click the button below to continue.</p>
</noscript>
<form id="f" method="POST" action="{{.RedirectURI}}">
<input type="hidden" name="code" value="{{.Code}}">
{{if .State}}<input type="hidden" name="state" value="{{.State}}">{{end}}
<input type="hidden" name="iss" value="{{.Iss}}">
<noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>
`))

// formPostData carries the values rendered into the response HTML.
// One struct (rather than a map) so html/template can pick the
// correct escaping context per field at parse time.
type formPostData struct {
	RedirectURI string
	Code        string
	State       string
	Iss         string
}

// renderFormPostResponse delivers the OIDC Form Post Response Mode
// 1.0 HTML for a successful authorization_code response. Called
// instead of ctx.JSON when response_mode=form_post.
func (s *Server) renderFormPostResponse(ctx HandlerContext, redirectURI, code, state string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = formPostTemplate.Execute(w, formPostData{
		RedirectURI: redirectURI,
		Code:        code,
		State:       state,
		Iss:         s.resolveIssuer(ctx),
	})
}

// isValidResponseMode reports whether the supplied `response_mode`
// value is one this server understands. Empty is always valid (it
// means "use the response_type-defined default") so callers MUST
// short-circuit on empty before this check.
func isValidResponseMode(mode string) bool {
	switch mode {
	case ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// OIDC userinfo signed-response (JWT) path.

// userinfoSignedAlgEdDSA is the only `userinfo_signed_response_alg`
// value this server can satisfy today — matches the access-token /
// id-token signing algorithm.
const userinfoSignedAlgEdDSA = "EdDSA"

// maybeSignUserInfo returns true when it has handled the response
// (signed JWT delivered to ctx) — callers MUST bail. False means
// the caller should fall through to the JSON response path.
//
// The signed-JWT path fires only when:
//   - clientID resolves to a registered client AND
//   - that client's UserinfoSignedResponseAlg is set AND
//   - the wired oidc.IDTokenIssuer implements oidc.UserinfoSigner
//
// Unsupported alg values (anything besides EdDSA) fall through to
// JSON — the spec says the AS MUST honor the request OR return JSON
// when it can't; we choose the latter to keep RPs working.
func (s *Server) maybeSignUserInfo(ctx HandlerContext, clientID string, body map[string]any) bool {
	if s.idTokenIssuer == nil || s.clientStore == nil || clientID == "" {
		return false
	}
	signer, ok := s.idTokenIssuer.(oidc.UserinfoSigner)
	if !ok {
		return false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || client == nil || client.UserinfoSignedResponseAlg == "" {
		return false
	}
	if client.UserinfoSignedResponseAlg != userinfoSignedAlgEdDSA {
		// Unsupported alg — fall through to JSON. The RP picks
		// up the misconfiguration from a discovery comparison.
		return false
	}
	jwt, err := signer.SignUserInfo(ctx.Request().Context(), client.ID, body)
	if err != nil {
		s.logger.Error("userinfo sign failed", "error", err, "client", client.ID)
		return false
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
	return true
}
