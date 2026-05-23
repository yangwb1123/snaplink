package sso

import (
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// urlQueryEscape wraps net/url.QueryEscape for callsites that want
// to compose query strings manually rather than build url.Values.
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// OIDC Front-Channel Logout 1.0.
//
// When the user logs out via /end_session and one or more clients
// the subject is signed into expose a FrontchannelLogoutURI, the
// response body is an HTML page with a hidden iframe per such
// client. The browser loads each URI; the RPs respond by clearing
// their own session cookies. After a short delay the page redirects
// to post_logout_redirect_uri if one was supplied and allowlisted —
// the delay gives every iframe time to fire its request before the
// user agent navigates away.
//
// Multi-RP fan-out mirrors BCL: when [WithSubjectClientIndex] is
// wired, gatherFrontchannelLogoutIframes walks the index and emits
// one iframe per FCL-capable client the subject has logged into
// across the cluster. Without the index, only the primary client
// (the one matched by id_token_hint / client_id_hint) gets an
// iframe — the original single-RP behavior is preserved as a
// graceful fallback.
//
// Caveats:
//
//   - sid claim only on the primary iframe. Fan-out targets get an
//     empty sid because the AS doesn't keep per-(subject, client)
//     session IDs in the security.SubjectClientIndex; FCL §3 allows sid
//     omission when the AS doesn't have one for that target.
//   - Fire-and-forget: the AS has no signal whether the iframes
//     actually cleared the RPs' sessions. Matches BCL's fail-open
//     posture — logout completes regardless of RP cooperation.

// frontchannelLogoutTemplate renders the OIDC FCL 1.0 §3 HTML
// response. The two-second meta-refresh is the working compromise:
// long enough for the iframes to issue their requests, short enough
// that users don't perceive a hang. html/template auto-escapes
// every iframe `src` and the `.RedirectURI` in their respective
// attribute contexts — `src=` and `href=` are URL-safe, the
// meta-refresh `content=` is HTML-escaped. Operator-controlled
// inputs only, but escaping is belt-and-braces against future
// client-supplied values.
var frontchannelLogoutTemplate = template.Must(template.New("fcl").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Logout</title>
{{if .RedirectURI}}<meta http-equiv="refresh" content="2; url={{.RedirectURI}}">{{end}}
</head>
<body>
{{range .IframeURIs}}<iframe src="{{.}}" style="display:none" referrerpolicy="no-referrer" sandbox="allow-same-origin allow-scripts"></iframe>
{{end}}{{if .RedirectURI}}<p>You will be redirected to <a href="{{.RedirectURI}}">{{.RedirectURI}}</a> shortly.</p>{{end}}
</body>
</html>
`))

// frontchannelLogoutData is the template input. IframeURIs is a
// pre-composed slice (each URI already has sid+iss query params
// appended where applicable); the template only iterates.
type frontchannelLogoutData struct {
	IframeURIs  []string
	RedirectURI string
}

// renderFrontchannelLogout writes the FCL HTML response. Always
// 200 OK — the logout already happened by the time we render; the
// HTML page is the side-effect carrier, not the operation. X-Frame-
// Options: DENY prevents an attacker from embedding our /end_session
// response in their own iframe to trick users into involuntary
// logout (a low-impact but real clickjacking vector).
//
// iframeURIs are pre-composed by gatherFrontchannelLogoutIframes
// with sid + iss query params per OIDC Front-Channel Logout 1.0 §3
// — sid disambiguates the RP's concurrent sessions, iss helps
// multi-issuer RPs route the logout.
func (s *Server) renderFrontchannelLogout(ctx HandlerContext, iframeURIs []string, redirectURI string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = frontchannelLogoutTemplate.Execute(w, frontchannelLogoutData{
		IframeURIs:  iframeURIs,
		RedirectURI: redirectURI,
	})
}

// gatherFrontchannelLogoutIframes returns the iframe URIs (with
// sid + iss query params appended) to render on the FCL page.
//
// The primary client — the one matched by id_token_hint /
// client_id_hint — comes first when it has a FrontchannelLogoutURI;
// it carries the sid from the inbound id_token so the RP can
// disambiguate which session to clear. When [WithSubjectClientIndex]
// is wired, every additional client the subject is logged into
// across the cluster contributes one more iframe (deduplicated;
// sorted for deterministic output). Fan-out targets get an empty
// sid — the AS doesn't keep per-(subject, client) session IDs in
// the index, and FCL §3 allows sid omission when the AS doesn't
// have one for that target.
//
// Returns an empty slice when no client has FCL configured; callers
// MUST check len(...) > 0 before deciding to render the HTML page
// (versus falling through to the 302 / 204 paths).
func (s *Server) gatherFrontchannelLogoutIframes(ctx HandlerContext, subject string, primary *Client, sid string) []string {
	iss := s.resolveIssuer(ctx)
	out := []string{}
	seen := map[string]bool{}
	if primary != nil && primary.FrontchannelLogoutURI != "" {
		out = append(out, appendFrontchannelLogoutSidIss(primary.FrontchannelLogoutURI, sid, iss))
		seen[primary.ID] = true
	}
	if s.subjectClientIndex == nil || subject == "" || s.clientStore == nil {
		return out
	}
	ids, err := s.subjectClientIndex.ListClients(ctx.Request().Context(), subject)
	if err != nil {
		s.logger.Error("subject_client_index: list failed (fcl fanout)", "error", err, "subject", subject)
		return out
	}
	sort.Strings(ids)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), id)
		if err != nil || c == nil || c.FrontchannelLogoutURI == "" {
			continue
		}
		out = append(out, appendFrontchannelLogoutSidIss(c.FrontchannelLogoutURI, "", iss))
		seen[id] = true
	}
	return out
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
