package oidc

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// jarmFormPostTemplate renders the JARM form_post.jwt auto-POST page.
// Mirrors the Form Post Response Mode template but carries the single
// signed `response` field. Field uses html/template attribute-value
// escaping so the JWT can't break out of the form.
//
// The auto-submit is a <script nonce="..."> tag rather than a
// <body onload="..."> attribute — see oidcsupport.formPostTemplate's doc for
// why (CSP's script-src has no 'unsafe-inline'; a nonce source only ever
// satisfies a <script> element, never an inline event-handler attribute).
var jarmFormPostTemplate = template.Must(template.New("jarmFormPost").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Submitting…</title>
</head>
<body>
<noscript>
<p>JavaScript is required to complete sign-in. Please click the button below to continue.</p>
</noscript>
<form id="f" method="POST" action="{{.RedirectURI}}">
<input type="hidden" name="response" value="{{.Response}}">
<noscript><button type="submit">Continue</button></noscript>
</form>
<script{{if .Nonce}} nonce="{{.Nonce}}"{{end}}>document.forms[0].submit()</script>
</body>
</html>
`))

// jarmFormPostData carries the values rendered into the JARM form_post
// page (one struct so html/template picks per-field escaping).
type jarmFormPostData struct {
	RedirectURI string
	Response    string
	// Nonce is the per-request CSP nonce (core.CSPNonceFromContext), empty
	// when security headers are not enabled for this request.
	Nonce string
}

// JARM response modes per JWT Secured Authorization Response Mode
// (JARM). `jwt` is the bare alias and resolves to the response_type's
// default delivery (query for the code flow this server runs); the
// dotted forms pin the delivery channel explicitly.
const (
	ResponseModeJWT         = "jwt"
	ResponseModeQueryJWT    = "query.jwt"
	ResponseModeFragmentJWT = "fragment.jwt"
	ResponseModeFormPostJWT = "form_post.jwt"
)

// IsJARMResponseMode reports whether mode is one of the JARM response
// modes (the bare `jwt` alias or a dotted `<delivery>.jwt`).
func IsJARMResponseMode(mode string) bool {
	switch mode {
	case ResponseModeJWT, ResponseModeQueryJWT, ResponseModeFragmentJWT, ResponseModeFormPostJWT:
		return true
	}
	return false
}

// JARMSigner is the seam JARM uses to sign the response JWT. It is a
// subset of oidc.MetadataSigner — the wired Ed25519JWTIssuer already
// satisfies it, so JARM reuses the same signing key as access / id /
// metadata without touching the issuer internals.
type JARMSigner interface {
	SignMetadata(ctx context.Context, claims map[string]any) (string, error)
}

// JARMDefaultTTL is the lifetime stamped into the JARM response JWT's
// exp claim. The response is consumed immediately by the RP on the
// redirect, so a short window suffices and bounds replay.
const JARMDefaultTTL = 10 * time.Minute

// SignJARMResponse builds and signs the JARM authorization response
// JWT. Per JARM §2.1 the JWT carries iss, aud (= client_id), exp plus
// the authorization response parameters (code, state). state is
// omitted when empty.
func SignJARMResponse(ctx context.Context, signer JARMSigner, issuer, clientID, code, state string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		core.KeyIss:  issuer,
		"aud":        clientID,
		"exp":        now.Add(JARMDefaultTTL).Unix(),
		"iat":        now.Unix(),
		core.KeyCode: code,
	}
	if state != "" {
		claims[core.KeyState] = state
	}
	return signer.SignMetadata(ctx, claims)
}

// SignJARMErrorResponse signs an authorization error into the same protected
// response shape as a successful JARM result. The redirect URI is validated by
// the SSO layer before this function is called.
func SignJARMErrorResponse(ctx context.Context, signer JARMSigner, issuer, clientID, code, description, state string) (string, error) {
	now := time.Now()
	claims := map[string]any{
		core.KeyIss:   issuer,
		"aud":         clientID,
		"exp":         now.Add(JARMDefaultTTL).Unix(),
		"iat":         now.Unix(),
		core.KeyError: code,
	}
	if description != "" {
		claims[core.KeyErrorDescription] = description
	}
	if state != "" {
		claims[core.KeyState] = state
	}
	return signer.SignMetadata(ctx, claims)
}

// RenderJARMResponse signs the authorization response into a JWT and
// delivers it as the single `response` parameter, per the requested
// delivery channel (query / fragment / form_post; the bare `jwt`
// alias resolves to query for the code flow). It returns false (and
// writes nothing) when signing fails, so the caller can fall through
// to a fail-closed error response.
func RenderJARMResponse(ctx core.HandlerContext, signer JARMSigner, responseMode, redirectURI, issuer, clientID, code, state string) bool {
	jwt, err := SignJARMResponse(ctx.Request().Context(), signer, issuer, clientID, code, state)
	if err != nil {
		return false
	}
	renderJARMJWT(ctx, responseMode, redirectURI, jwt)
	return true
}

// RenderJARMErrorResponse signs and delivers a protected authorization error.
func RenderJARMErrorResponse(ctx core.HandlerContext, signer JARMSigner, responseMode, redirectURI, issuer, clientID, code, description, state string) bool {
	jwt, err := SignJARMErrorResponse(ctx.Request().Context(), signer, issuer, clientID, code, description, state)
	if err != nil {
		return false
	}
	renderJARMJWT(ctx, responseMode, redirectURI, jwt)
	return true
}

func renderJARMJWT(ctx core.HandlerContext, responseMode, redirectURI, jwt string) {
	switch responseMode {
	case ResponseModeFormPostJWT:
		renderJARMFormPost(ctx, redirectURI, jwt)
	case ResponseModeFragmentJWT:
		renderJARMRedirect(ctx, redirectURI, jwt, true)
	default:
		// ResponseModeJWT + ResponseModeQueryJWT: query delivery, the
		// default for response_type=code.
		renderJARMRedirect(ctx, redirectURI, jwt, false)
	}
}

// renderJARMRedirect issues a 302 to redirect_uri carrying the signed
// response in `response` either on the query string or the fragment.
func renderJARMRedirect(ctx core.HandlerContext, redirectURI, jwt string, fragment bool) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// redirect_uri was already validated against the client before
		// this point; a parse failure here is unreachable, but fail
		// safe with a plain body rather than a broken Location.
		w := ctx.ResponseWriter()
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	enc := url.Values{KeyResponse: {jwt}}.Encode()
	if fragment {
		u.Fragment = KeyResponse + "=" + url.QueryEscape(jwt)
	} else {
		if u.RawQuery == "" {
			u.RawQuery = enc
		} else {
			u.RawQuery += "&" + enc
		}
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusFound)
}

// renderJARMFormPost reuses the Form Post Response Mode auto-POST page
// but carries the single signed `response` field instead of the bare
// code/state/iss parameters.
func renderJARMFormPost(ctx core.HandlerContext, redirectURI, jwt string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = jarmFormPostTemplate.Execute(w, jarmFormPostData{
		RedirectURI: redirectURI,
		Response:    jwt,
		Nonce:       core.CSPNonceFromContext(ctx.Request().Context()),
	})
}

// KeyResponse is the JARM authorization response parameter name (the
// signed JWT is carried as `response`).
const KeyResponse = "response"
