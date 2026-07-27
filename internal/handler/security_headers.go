package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// SecurityHeadersPolicy is the operator-customizable part of the
// SecurityHeaders middleware: the Content-Security-Policy directive list and
// the Permissions-Policy header value. The zero value is not meant to be used
// directly by callers outside this package — SecurityHeaders fills in
// DefaultSecurityHeadersPolicy's values for whichever field is left empty, so
// sso.WithSecurityHeadersPolicy lets an operator override just one of the two
// without having to restate the other.
type SecurityHeadersPolicy struct {
	// CSPDirectives is the ordered list of Content-Security-Policy directives
	// (e.g. "default-src 'self'"), joined with "; " into the header value. A
	// fresh per-request nonce is appended to whichever directive governs
	// scripts — script-src if present, else default-src, else a new
	// script-src directive is added — as 'nonce-<value>' so an inline
	// <script nonce="..."> tag (the OIDC form_post / JARM auto-submit pages
	// use one instead of an inline event-handler attribute) verifies without
	// the policy needing 'unsafe-inline'. Nil (the zero value) falls back to
	// DefaultSecurityHeadersPolicy's directives.
	CSPDirectives []string
	// PermissionsPolicy is the raw Permissions-Policy header value. Empty
	// (the zero value) falls back to DefaultSecurityHeadersPolicy's value.
	PermissionsPolicy string
}

// DefaultSecurityHeadersPolicy is the SDK's conservative-by-default CSP +
// Permissions-Policy, applied whenever WithSecurityHeaders is used without
// WithSecurityHeadersPolicy overriding a field. It only allows same-origin
// resources (script/style/img/font/connect), denies framing entirely
// (frame-ancestors 'none', belt-and-suspenders with the X-Frame-Options
// header below) and plugin content (object-src 'none'). script-src does NOT
// carry 'unsafe-inline': the bundled admin/login/portal SPAs load only
// external same-origin <script src>, and the OIDC form_post/JARM pages use a
// nonce-tagged <script> instead of an inline event-handler attribute — so a
// strict script-src holds without weakening it. style-src keeps
// 'unsafe-inline' because those same SPAs use inline style="" attributes for
// simple show/hide toggles; CSP has no nonce mechanism for style ATTRIBUTES
// (only <style> elements), so tightening that would need every toggle
// rewritten as a CSS class first.
func DefaultSecurityHeadersPolicy() SecurityHeadersPolicy {
	return SecurityHeadersPolicy{
		CSPDirectives: []string{
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'",
			"img-src 'self' data:",
			"font-src 'self'",
			"connect-src 'self'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
		},
		PermissionsPolicy: "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
	}
}

// resolve fills any empty field of p from DefaultSecurityHeadersPolicy,
// leaving an operator-supplied non-empty field untouched.
func (p SecurityHeadersPolicy) resolve() SecurityHeadersPolicy {
	if len(p.CSPDirectives) == 0 || p.PermissionsPolicy == "" {
		def := DefaultSecurityHeadersPolicy()
		if len(p.CSPDirectives) == 0 {
			p.CSPDirectives = def.CSPDirectives
		}
		if p.PermissionsPolicy == "" {
			p.PermissionsPolicy = def.PermissionsPolicy
		}
	}
	return p
}

// cspNonceBytes is the size in bytes of the per-request nonce before
// base64 encoding (16 bytes -> 24 base64 chars), comfortably above the
// 128-bit minimum CSP Level 3 recommends for a nonce source.
const cspNonceBytes = 16

// newCSPNonce returns a fresh cryptographically random, base64-encoded
// per-request CSP nonce.
func newCSPNonce() string {
	var b [cspNonceBytes]byte
	_, _ = rand.Read(b[:])
	return base64.StdEncoding.EncodeToString(b[:])
}

// SecurityHeaders adds browser-security headers — including a per-request CSP
// nonce — to every response the wrapped handler produces. Headers already set
// by inner handlers are NOT overwritten (so existing per-handler
// X-Frame-Options: DENY on form_post/jarm survive, and credential endpoints'
// Cache-Control: no-store is untouched — this middleware is purely
// additive). HSTS is only added when the request arrived over TLS
// (r.TLS != nil) to avoid breaking the dev HTTP workflow.
//
// A fresh nonce is minted per request (crypto/rand) and stored in the
// request context via core.WithCSPNonce BEFORE calling next, so any handler
// downstream — including the OIDC form_post / JARM HTML renderers — can read
// it back with core.CSPNonceFromContext and stamp it onto an inline
// <script nonce="..."> tag that matches the CSP header this middleware sets.
func SecurityHeaders(policy SecurityHeadersPolicy) func(http.Handler) http.Handler {
	policy = policy.resolve()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := newCSPNonce()
			r = r.WithContext(core.WithCSPNonce(r.Context(), nonce))
			w2 := &securityHeadersWriter{ResponseWriter: w, policy: policy, nonce: nonce}
			// HSTS must be set before WriteHeader so it survives a
			// handler calling WriteHeader + Write directly.
			if r.TLS != nil {
				w2.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w2, r)
		})
	}
}

// securityHeadersWriter sets security-related response headers only when
// the inner handler has NOT already set them. This prevents the middleware
// from overwriting Cache-Control: no-store on credential endpoints or
// per-handler X-Frame-Options: DENY on form-post pages.
type securityHeadersWriter struct {
	http.ResponseWriter
	policy SecurityHeadersPolicy
	nonce  string
}

// WriteHeader sets the default-deny security headers — plus CSP and
// Permissions-Policy — that are not already present on the response, then
// delegates to the real WriteHeader.
func (w *securityHeadersWriter) WriteHeader(code int) {
	h := w.Header()
	if h.Get("X-Content-Type-Options") == "" {
		h.Set("X-Content-Type-Options", "nosniff")
	}
	if h.Get("X-Frame-Options") == "" {
		h.Set("X-Frame-Options", "DENY")
	}
	if h.Get("Referrer-Policy") == "" {
		h.Set("Referrer-Policy", "no-referrer")
	}
	if h.Get("Content-Security-Policy") == "" {
		h.Set("Content-Security-Policy", buildCSP(w.policy.CSPDirectives, w.nonce))
	}
	if h.Get("Permissions-Policy") == "" && w.policy.PermissionsPolicy != "" {
		h.Set("Permissions-Policy", w.policy.PermissionsPolicy)
	}
	w.ResponseWriter.WriteHeader(code)
}

// buildCSP joins directives into a Content-Security-Policy header value,
// appending 'nonce-<nonce>' to whichever directive governs script execution
// (script-src if present, else default-src, else a new script-src directive)
// so the returned value always lets a nonce-tagged inline <script> run
// without the policy needing 'unsafe-inline'.
func buildCSP(directives []string, nonce string) string {
	out := make([]string, len(directives))
	copy(out, directives)
	if i := cspDirectiveIndex(out, "script-src"); i >= 0 {
		out[i] += " 'nonce-" + nonce + "'"
	} else if i := cspDirectiveIndex(out, "default-src"); i >= 0 {
		out[i] += " 'nonce-" + nonce + "'"
	} else {
		out = append(out, "script-src 'nonce-"+nonce+"'")
	}
	return strings.Join(out, "; ")
}

// cspDirectiveIndex returns the index of the directive named prefix (e.g.
// "script-src"), or -1 when none of the directives start with it.
func cspDirectiveIndex(directives []string, prefix string) int {
	for i, d := range directives {
		if strings.HasPrefix(d, prefix) {
			return i
		}
	}
	return -1
}
