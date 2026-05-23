package sso

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/spi"
)

func AuthMiddleware(tokenIssuer TokenIssuer) MiddlewareFunc {
	return func(ctx HandlerContext) {
		auth := ctx.Request().Header.Get(HeaderAuthorization)
		if auth == "" || !strings.HasPrefix(auth, BearerPrefix) {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrUnauthorized))
			return
		}

		token := strings.TrimPrefix(auth, BearerPrefix)
		if _, err := tokenIssuer.Validate(ctx.Request().Context(), token); err != nil {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
			return
		}
	}
}

// CORS adds CORS headers to responses.
func CORS(allowedOrigins []string) MiddlewareFunc {
	return func(ctx HandlerContext) {
		w := ctx.ResponseWriter()
		origin := ctx.Request().Header.Get("Origin")

		for _, o := range allowedOrigins {
			if o == CORSAllowAllOrigin || o == origin {
				w.Header().Set(HeaderAccessControlOrigin, o)
				break
			}
		}

		w.Header().Set(HeaderAccessControlMethods, CORSAllowedMethods)
		w.Header().Set(HeaderAccessControlHeaders, CORSAllowedHeaders)

		if ctx.Request().Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
}

// LoggerMiddleware logs each request.
func LoggerMiddleware(l spi.Logger) MiddlewareFunc {
	return func(ctx HandlerContext) {
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

// TracingMiddleware combines two correlation strategies:
//
//   - X-Request-Id (one HTTP hop) — preserve incoming, otherwise generate.
//   - W3C Traceparent (full call chain) — preserve incoming trace, but
//     create a fresh span here so downstream calls see us as the parent.
//
// Both flow back to the caller via response headers and into the request
// header so audit helpers (auditEventFromRequest) can pick them up without
// extra plumbing.
func TracingMiddleware() MiddlewareFunc {
	return func(ctx HandlerContext) {
		r := ctx.Request()
		w := ctx.ResponseWriter()

		// Request ID (single hop).
		reqID := r.Header.Get(HeaderRequestID)
		if reqID == "" {
			reqID = newRequestID()
			r.Header.Set(HeaderRequestID, reqID)
		}
		w.Header().Set(HeaderRequestID, reqID)

		// Trace context (full chain).
		var parent audit.TraceContext
		if h := r.Header.Get(HeaderTraceparent); h != "" {
			if tc, err := tracer.ParseTraceparent(h); err == nil {
				parent = tc
			}
		}
		current := tracer.StartChild(parent)
		r.Header.Set(HeaderTraceparent, tracer.FormatTraceparent(current))
		w.Header().Set(HeaderTraceparent, tracer.FormatTraceparent(current))
		if current.ParentSpanID != "" {
			r.Header.Set(HeaderParentSpanID, current.ParentSpanID)
		}
	}
}

// RequestIDMiddleware is kept as a back-compat alias of TracingMiddleware.
// New code should call TracingMiddleware directly.
func RequestIDMiddleware() MiddlewareFunc { return TracingMiddleware() }

func newRequestID() string {
	var b [requestIDBytes]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
