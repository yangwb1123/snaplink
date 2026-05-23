package middleware

import (
	"net/http"
	"strings"
)

// BaseURL derives an absolute scheme://host base from the request.
// Honors X-Forwarded-Proto / X-Forwarded-Host from a known edge
// proxy; falls back to req.TLS for scheme and req.Host otherwise.
//
// Internet-facing deployments without an edge proxy that strips and
// re-sets those headers MUST install a stricter base extractor —
// XFF spoofing on a public endpoint can serve the wrong scheme to
// OIDC RPs (clients then refuse the discovery doc on issuer
// mismatch, or worse, accept an attacker-controlled origin).
func BaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		// First hop only — some chains comma-separate.
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		scheme = strings.TrimSpace(v)
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		host = strings.TrimSpace(v)
	}
	return scheme + "://" + host
}
