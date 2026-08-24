// Package middleware holds the general HTTP middleware functions
// — bearer-token validation, CORS, logging, panic recovery,
// and request correlation (OTel span + request ID). Domain-specific
// middleware (admin auth, tenant resolution, geo enrichment) lives
// in their respective subpackages (admin/, tenant/, geo/).
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/yangwb1123/snaplink/platform/tracing"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
	"go.opentelemetry.io/otel/trace"
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
// return 401 with the standard {error: invalid_token} body and abort the
// chain so the handler never runs after a rejection (without Abort the
// handler would write a second response on top of the 401).
func Auth(tokenIssuer core.TokenIssuer) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		auth := ctx.Request().Header.Get(core.HeaderAuthorization)
		if auth == "" || !strings.HasPrefix(auth, core.BearerPrefix) {
			ctx.JSON(http.StatusUnauthorized, map[string]string{core.KeyError: core.ErrUnauthorized})
			ctx.Abort()
			return
		}

		token := strings.TrimPrefix(auth, core.BearerPrefix)
		if _, err := tokenIssuer.Validate(ctx.Request().Context(), token); err != nil {
			ctx.JSON(http.StatusUnauthorized, map[string]string{core.KeyError: core.ErrInvalidToken})
			ctx.Abort()
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
			ctx.Abort()
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

// Correlation is the ONE middleware that ties a request to a trace and a
// request ID (Decision 7 of docs/design/middleware-observability-unified.md).
// It wraps tracing.Middleware (the otelhttp span) and, from the LIVE span
// context, stamps:
//   - request context: core.WithTraceID (error bodies keep their trace_id)
//   - response headers: X-Trace-Id (trace ID) and X-Request-Id
//   - request header: X-Request-Id (preserve incoming, else generate 32-hex)
//
// It no longer parses or rewrites Traceparent, and it does not build its
// own trace context — the OTel span is the only source of truth. With the
// SDK's no-op provider (no tracing.Init endpoint) the span context is
// invalid: X-Trace-Id/Traceparent stay absent and audit/access-log trace
// IDs are empty — the honest "no tracing" state — while X-Request-Id and
// audit RequestID keep working in every shape (Decision 12 semantics).
//
// interfaces/middleware is at its 10-file ceiling, so this lives in
// middleware.go (the file that previously held the deleted legacy
// Tracing/RequestID surface) instead of a new correlation.go — same drift
// ruling B11 recorded for accesslog.go → request_log.go.
func Correlation(operation string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// The inner handlerfunc runs while the otelhttp span is live, so the
		// span context read here is the request's own span — the single
		// source of truth for X-Trace-Id, context trace_id, and the
		// Traceparent response header. otelhttp v0.68.0 does not inject the
		// response header itself (verified upstream: handler.go has no
		// propagator.Inject on the response), so the wrapper owns that wire
		// contract explicitly — the design's documented fallback.
		return tracing.Middleware(operation)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := r.Header.Get(core.HeaderRequestID)
			if reqID == "" {
				reqID = newRequestID()
				r.Header.Set(core.HeaderRequestID, reqID)
			}
			w.Header().Set(core.HeaderRequestID, reqID)
			if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() && sc.HasTraceID() {
				// Mutate the request struct IN PLACE (same pointer the
				// access logger and handlers hold downstream) so the trace
				// ID survives the otelhttp WithContext rebind — the pattern
				// the legacy Tracing middleware used at router level.
				*r = *r.WithContext(core.WithTraceID(r.Context(), sc.TraceID().String()))
				w.Header().Set(core.HeaderTraceID, sc.TraceID().String())
				w.Header().Set(core.HeaderTraceparent, formatTraceparent(sc))
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// formatTraceparent renders a W3C traceparent from a live span context.
// Flags carry the span's actual sampled bit — an unsampled span emits
// "00" (downstream honors the head-sampling decision), never a forged 01.
func formatTraceparent(sc trace.SpanContext) string {
	return "00-" + sc.TraceID().String() + "-" + sc.SpanID().String() + "-" + fmt.Sprintf("%02x", sc.TraceFlags())
}

// newRequestID returns a fresh 32-hex request ID (16 random bytes). Moved
// here with the legacy Tracing/RequestID surface per Decision 7's removal
// list; the generator is unchanged.
func newRequestID() string {
	var b [requestIDBytes]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
