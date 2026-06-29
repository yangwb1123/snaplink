package handler

import "net/http"

// SecurityHeaders adds browser-security headers to every response.
// Headers already set by inner handlers are NOT overwritten (so existing
// per-handler X-Frame-Options: DENY on form_post/jarm survive).
// HSTS is only added when the request arrived over TLS (r.TLS != nil)
// to avoid breaking the dev HTTP workflow.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w2 := &securityHeadersWriter{ResponseWriter: w}
		// HSTS must be set before WriteHeader so it survives a
		// handler calling WriteHeader + Write directly.
		if r.TLS != nil {
			w2.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w2, r)
	})
}

// securityHeadersWriter sets security-related response headers only when
// the inner handler has NOT already set them. This prevents the middleware
// from overwriting Cache-Control: no-store on credential endpoints or
// per-handler X-Frame-Options: DENY on form-post pages.
type securityHeadersWriter struct {
	http.ResponseWriter
}

// WriteHeader sets the three default-deny security headers that are not
// already present on the response, then delegates to the real WriteHeader.
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
	w.ResponseWriter.WriteHeader(code)
}
