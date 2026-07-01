package middleware

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

// requestLogResponseWriter captures the response body and status code
// so the debug-logging middleware can record them.
type requestLogResponseWriter struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func (w *requestLogResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *requestLogResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	if w.body != nil {
		w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// RequestLogger returns an http.Handler middleware that logs request and
// response metadata at DEBUG level — method, path, query, status, duration,
// request body, and response body (when bodies are enabled). Designed for
// development and production-troubleshooting; the log volume may be high,
// so only enable when actively investigating an issue or on low-traffic
// endpoints (e.g. a debug listener).
//
// logBodies controls whether the request body and response body are included
// in the log entry (disabled by default because bodies may contain secrets
// such as passwords, tokens, or MFA codes).
func RequestLogger(l spi.Logger, logBodies bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Read the request body (if logging bodies is enabled).
			var reqBody string
			if logBodies && r.Body != nil {
				b, err := io.ReadAll(r.Body)
				if err == nil {
					reqBody = string(b)
					// Restore the body for downstream handlers.
					r.Body = io.NopCloser(bytes.NewReader(b))
				}
			}

			// Wrap the response writer to capture status + body.
			rlw := &requestLogResponseWriter{
				ResponseWriter: w,
				body:           nil,
			}
			if logBodies {
				rlw.body = &bytes.Buffer{}
			}

			next.ServeHTTP(rlw, r)

			dur := time.Since(start)
			fields := []any{
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"status", rlw.statusCode,
				"duration", dur.String(),
			}
			if logBodies {
				if reqBody != "" {
					fields = append(fields, "request_body", reqBody)
				}
				if rlw.body != nil && rlw.body.Len() > 0 {
					fields = append(fields, "response_body", rlw.body.String())
				}
			}
			l.Debug("request", fields...)
		})
	}
}
