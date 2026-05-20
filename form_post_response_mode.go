package sso

import (
	"html/template"
	"net/http"
)

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
