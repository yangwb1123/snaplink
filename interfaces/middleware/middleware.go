// Package middleware holds the general HTTP middleware functions
// — bearer-token validation, CORS, logging, panic recovery,
// and W3C trace context propagation. Domain-specific middleware
// (admin auth, tenant resolution, geo enrichment) lives in their
// respective subpackages (admin/, tenant/, geo/).
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Recover catches panics from downstream handlers and middlewares,
// logs the stack trace, and returns 500 to the client instead of
// crashing the process. Install as the outermost middleware wrapper
// so it catches panics from every layer below.
//
// The standard-library Context ensures the ResponseWriter and Request
// survive a panicking handler; ctx.JSON writes the error to the client.
func Recover(l spi.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					stack := debug.Stack()
					l.Error("panic recovered",
						"panic", rec,
						"stack", string(stack),
						"path", r.URL.Path,
					)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"` + core.ErrInternal + `"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Auth validates Bearer tokens on protected routes. Failures
// return 401 with the standard {error: invalid_token} body.
func Auth(tokenIssuer core.TokenIssuer) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		auth := ctx.Request().Header.Get(core.HeaderAuthorization)
		if auth == "" || !strings.HasPrefix(auth, core.BearerPrefix) {
			ctx.JSON(http.StatusUnauthorized, map[string]string{core.KeyError: core.ErrUnauthorized})
			return
		}

		token := strings.TrimPrefix(auth, core.BearerPrefix)
		if _, err := tokenIssuer.Validate(ctx.Request().Context(), token); err != nil {
			ctx.JSON(http.StatusUnauthorized, map[string]string{core.KeyError: core.ErrInvalidToken})
			return
		}
	}
}

// CORS adds CORS headers to responses.
func CORS(allowedOrigins []string) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		w := ctx.ResponseWriter()
		origin := ctx.Request().Header.Get("Origin")

		for _, o := range allowedOrigins {
			if o == core.CORSAllowAllOrigin || o == origin {
				w.Header().Set(core.HeaderAccessControlOrigin, o)
				break
			}
		}

		w.Header().Set(core.HeaderAccessControlMethods, core.CORSAllowedMethods)
		w.Header().Set(core.HeaderAccessControlHeaders, core.CORSAllowedHeaders)

		if ctx.Request().Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
}

// Logger logs each request.
func Logger(l spi.Logger) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		l.Info("request",
			"method", ctx.Request().Method,
			"path", ctx.Request().URL.Path,
		)
	}
}

// requestIDBytes is the size in bytes of generated IDs (16 → 32 hex chars).
const requestIDBytes = 16

// tracer is the package-level helper for parsing/formatting W3C traceparent.
// Stateless — safe to share.
var tracer = audit.NewTracer()

// Tracing combines two correlation strategies:
//
//   - X-Request-Id (one HTTP hop) — preserve incoming, otherwise generate.
//   - W3C Traceparent (full call chain) — preserve incoming trace, but
//     create a fresh span here so downstream calls see us as the parent.
//
// Both flow back to the caller via response headers and into the request
// header so audit helpers can pick them up without extra plumbing.
func Tracing() core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		r := ctx.Request()
		w := ctx.ResponseWriter()

		// Request ID (single hop).
		reqID := r.Header.Get(core.HeaderRequestID)
		if reqID == "" {
			reqID = newRequestID()
			r.Header.Set(core.HeaderRequestID, reqID)
		}
		w.Header().Set(core.HeaderRequestID, reqID)

		// Trace context (full chain).
		var parent audit.TraceContext
		if h := r.Header.Get(core.HeaderTraceparent); h != "" {
			if tc, err := tracer.ParseTraceparent(h); err == nil {
				parent = tc
			}
		}
		current := tracer.StartChild(parent)

		// Store the trace ID in the request context so error handlers
		// and audit helpers can surface it to the caller.
		*r = *r.WithContext(core.WithTraceID(r.Context(), current.TraceID))

		r.Header.Set(core.HeaderTraceparent, tracer.FormatTraceparent(current))
		w.Header().Set(core.HeaderTraceparent, tracer.FormatTraceparent(current))
		// X-Trace-Id is the human-facing trace identifier — a stable,
		// concise value the client can relay to support for debugging.
		// It is the W3C TraceID portion of the traceparent, trimmed to
		// a readable prefix length.
		w.Header().Set(core.HeaderTraceID, current.TraceID)
		if current.ParentSpanID != "" {
			r.Header.Set(core.HeaderParentSpanID, current.ParentSpanID)
		}
	}
}

// RequestID is kept as a back-compat alias of Tracing.
// New code should call Tracing directly.
func RequestID() core.MiddlewareFunc { return Tracing() }

func newRequestID() string {
	var b [requestIDBytes]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
