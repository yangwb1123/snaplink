package sso

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// urlQueryEscape wraps net/url.QueryEscape for callsites that want
// to compose query strings manually rather than build url.Values.
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// OIDC Front-Channel Logout 1.0 — single-RP single-iframe variant.
//
// When the user logs out via /end_session and the resolved client
// has a FrontchannelLogoutURI configured, the response body is an
// HTML page with a hidden iframe pointing at that URI. The browser
// loads the URI; the RP responds by clearing its own session
// cookies. After a short delay the page redirects to
// post_logout_redirect_uri if one was supplied and allowlisted —
// the delay gives the iframe time to fire its request before the
// user agent navigates away.
//
// Caveats (deliberate v1 scope):
//
//   - Single RP only — same scope as BCL today. Multi-RP fan-out
//     needs a subject → active-clients index, future work.
//   - `iss` / `sid` query params not stamped on the iframe URI.
//     The spec ties them to frontchannel_logout_session_supported,
//     which stays false until access tokens carry a sid claim.
//   - Fire-and-forget: the AS has no signal whether the iframe
//     actually cleared the RP's session. This matches BCL's
//     fail-open posture — logout completes regardless.

// frontchannelLogoutTemplate renders the OIDC FCL 1.0 §3 HTML
// response. The two-second meta-refresh is the working compromise:
// long enough for the iframe to issue its request, short enough
// that users don't perceive a hang. html/template auto-escapes
// `.IframeURI` and `.RedirectURI` in their respective attribute
// contexts — `src=` and `href=` are URL-safe, the meta-refresh
// `content=` is HTML-escaped. Operator-controlled inputs only,
// but escaping is belt-and-braces against future client-supplied
// values.
var frontchannelLogoutTemplate = template.Must(template.New("fcl").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Logout</title>
{{if .RedirectURI}}<meta http-equiv="refresh" content="2; url={{.RedirectURI}}">{{end}}
</head>
<body>
<iframe src="{{.IframeURI}}" style="display:none" referrerpolicy="no-referrer" sandbox="allow-same-origin allow-scripts"></iframe>
{{if .RedirectURI}}<p>You will be redirected to <a href="{{.RedirectURI}}">{{.RedirectURI}}</a> shortly.</p>{{end}}
</body>
</html>
`))

// frontchannelLogoutData is the template input.
type frontchannelLogoutData struct {
	IframeURI   string
	RedirectURI string
}

// renderFrontchannelLogout writes the FCL HTML response. Always
// 200 OK — the logout already happened by the time we render; the
// HTML page is the side-effect carrier, not the operation. X-Frame-
// Options: DENY prevents an attacker from embedding our /end_session
// response in their own iframe to trick users into involuntary
// logout (a low-impact but real clickjacking vector).
//
// Per OIDC Front-Channel Logout 1.0 §3, when the AS supports
// session identifiers, the iframe URI carries `sid` + `iss` query
// parameters so the RP can disambiguate which of its concurrent
// sessions to clear (sid) and which OP issued the original session
// (iss, helpful for multi-issuer RPs).
func (s *Server) renderFrontchannelLogout(ctx HandlerContext, iframeURI, redirectURI, sid string) {
	iframeURI = appendFrontchannelLogoutSidIss(iframeURI, sid, s.resolveIssuer(ctx))
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = frontchannelLogoutTemplate.Execute(w, frontchannelLogoutData{
		IframeURI:   iframeURI,
		RedirectURI: redirectURI,
	})
}

// appendFrontchannelLogoutSidIss appends `sid` + `iss` query params
// to the iframe URI when present. Both empty = return URI unchanged.
// Preserves any pre-existing query string on the RP-registered URI.
func appendFrontchannelLogoutSidIss(uri, sid, iss string) string {
	if sid == "" && iss == "" {
		return uri
	}
	var params []string
	if sid != "" {
		params = append(params, "sid="+urlQueryEscape(sid))
	}
	if iss != "" {
		params = append(params, "iss="+urlQueryEscape(iss))
	}
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + strings.Join(params, "&")
}

