package oidc

import (
	"html/template"
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// formPostTemplate renders the OIDC Form Post Response Mode 1.0
// auto-POST HTML page. The form elements are scoped via id="f" so
// the noscript fallback button's `form="f"` association keeps
// working even though the button itself lives outside the form
// (HTML5 spec). Every field uses html/template's default contextual
// escaping (attribute value=), so an attacker can't break out of
// the form fields.
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

// FormPostData carries the values rendered into the response HTML.
// One struct (rather than a map) so html/template can pick the
// correct escaping context per field at parse time.
type FormPostData struct {
	RedirectURI string
	Code        string
	State       string
	Iss         string
}

// RenderFormPostResponse writes the OIDC Form Post Response Mode 1.0
// HTML for a successful authorization_code response. Called instead
// of ctx.JSON when response_mode=form_post.
//
// Hardens response headers: X-Frame-Options: DENY (clickjacking) +
// Cache-Control: no-store + Referrer-Policy: no-referrer (don't leak
// the AS's URL to the RP via Referer; the auth response itself is
// what the RP needs).
func RenderFormPostResponse(ctx core.HandlerContext, redirectURI, code, state, iss string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = formPostTemplate.Execute(w, FormPostData{
		RedirectURI: redirectURI,
		Code:        code,
		State:       state,
		Iss:         iss,
	})
}
