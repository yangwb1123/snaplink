package middleware

import (
	"bytes"
	"context"
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

type idempotencyKey struct{}

// WithIdempotencyKey stores the idempotency key and cache in the context.
func WithIdempotencyKey(ctx context.Context, key string, cache core.IdempotentCache) context.Context {
	return context.WithValue(ctx, idempotencyKey{}, [2]any{key, cache})
}

// IdempotencyKeyFromContext extracts the idempotency key and cache.
func IdempotencyKeyFromContext(ctx context.Context) (string, core.IdempotentCache) {
	v, _ := ctx.Value(idempotencyKey{}).([2]any)
	if len(v) != 2 {
		return "", nil
	}
	key, _ := v[0].(string)
	cache, _ := v[1].(core.IdempotentCache)
	return key, cache
}

// idempotentResponseWriter wraps http.ResponseWriter to capture body.
type idempotentResponseWriter struct {
	http.ResponseWriter
	body       bytes.Buffer
	statusCode int
}

func (w *idempotentResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *idempotentResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// Idempotency returns a core.MiddlewareFunc that:
//  1. Checks for Idempotency-Key header
//  2. Returns cached response when available
//  3. Wraps the ResponseWriter to capture the response
//  4. Stores key+cache in request context for the handler
//
// NOTE: because StdRouter runs all middlewares then the handler,
// middleware cannot prevent the handler from executing. This middleware
// sets up the capture infrastructure; the handler (or a wrapper) must
// call HandleIdempotentRequest for the cache-hit shortcut.
// For endpoints where the handler cannot be easily modified, use
// HandleIdempotentRequest at the handler entrance.
func Idempotency(cache core.IdempotentCache) core.MiddlewareFunc {
	if cache == nil {
		return func(ctx core.HandlerContext) {}
	}
	return func(ctx core.HandlerContext) {
		r := ctx.Request()
		key := r.Header.Get(core.HeaderIdempotencyKey)
		if key == "" {
			return
		}
		// Store in context for the handler.
		*r = *r.WithContext(WithIdempotencyKey(r.Context(), key, cache))
		// Wrap ResponseWriter.
		if c, ok := ctx.(*core.Context); ok {
			c.SetResponseWriter(&idempotentResponseWriter{
				ResponseWriter: ctx.ResponseWriter(),
			})
		}
	}
}

// HandleIdempotentRequest checks the idempotency cache at the handler
// entry. Returns true when the response was already written (cached
// hit) and the handler should return immediately.
//
// Usage:
//
//	func (s *Server) handleAdminCreateClient(ctx HandlerContext) {
//	    if middleware.HandleIdempotentRequest(ctx) {
//	        return
//	    }
//	    // ... normal handler logic ...
//	}
func HandleIdempotentRequest(ctx core.HandlerContext) bool {
	key, cache := IdempotencyKeyFromContext(ctx.Request().Context())
	if key == "" || cache == nil {
		return false
	}
	if cached, ok, _ := cache.Get(ctx.Request().Context(), key); ok && len(cached) > 0 {
		w := ctx.ResponseWriter()
		w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cached)
		return true
	}
	return false
}

// CommitIdempotentResponse caches the captured response after the
// handler returns a 2xx. Call after the handler's ctx.JSON().
func CommitIdempotentResponse(ctx core.HandlerContext, statusCode int) {
	key, cache := IdempotencyKeyFromContext(ctx.Request().Context())
	if key == "" || cache == nil {
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		return
	}
	if iw, ok := ctx.ResponseWriter().(*idempotentResponseWriter); ok && iw.body.Len() > 0 {
		_ = cache.Set(ctx.Request().Context(), key, iw.body.Bytes(), 0)
	}
}
