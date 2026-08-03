package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

type idempotencyKey struct{}

// idempotencyState is the per-request idempotency state: the key, the
// cache, the installed capture wrapper, and the optional audit recorder
// backing the loud-commit event. It travels in the REQUEST CONTEXT, not
// in the ResponseWriter type — after SetResponseWriter the capture sits
// behind backend facades (gin) or response objects (echo), so a concrete
// assertion on ctx.ResponseWriter() cannot locate it (this is exactly
// what silently broke capture under the adapters before). One struct
// value keeps the context key cardinality at one per request.
type idempotencyState struct {
	key     string
	cache   core.IdempotentCache
	capture *CaptureWriter
	rec     *audit.Recorder
}

func withIdempotencyState(ctx context.Context, st idempotencyState) context.Context {
	return context.WithValue(ctx, idempotencyKey{}, st)
}

func idempotencyStateFromContext(ctx context.Context) (idempotencyState, bool) {
	st, ok := ctx.Value(idempotencyKey{}).(idempotencyState)
	return st, ok
}

// WithIdempotencyKey stores the idempotency key and cache in the context.
// The capture slot stays empty — it is filled by InstallCapture.
func WithIdempotencyKey(ctx context.Context, key string, cache core.IdempotentCache) context.Context {
	return withIdempotencyState(ctx, idempotencyState{key: key, cache: cache})
}

// IdempotencyKeyFromContext extracts the idempotency key and cache.
func IdempotencyKeyFromContext(ctx context.Context) (string, core.IdempotentCache) {
	st, ok := idempotencyStateFromContext(ctx)
	if !ok {
		return "", nil
	}
	return st.key, st.cache
}

// CaptureWriter wraps http.ResponseWriter to capture the response body and
// status for idempotency replay. Installed via InstallCapture; committed
// via CommitCapturedBody / CommitIdempotentResponse. The single capture
// implementation shared by the generic Idempotency middleware and the sso
// /token path (whose idempotentResponseWriter this type replaces).
type CaptureWriter struct {
	http.ResponseWriter
	body       bytes.Buffer
	statusCode int
	unlock     func()
}

func (w *CaptureWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *CaptureWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// StatusCode returns the status recorded on the first WriteHeader
// (http.StatusOK when only Write ran).
func (w *CaptureWriter) StatusCode() int { return w.statusCode }

// Body returns the captured response body.
func (w *CaptureWriter) Body() []byte { return w.body.Bytes() }

// Unlock releases the single-flight lock this request holds, when the
// capture was installed with one (the /token path). Nil-safe: the generic
// middleware installs no lock.
func (w *CaptureWriter) Unlock() {
	if w.unlock != nil {
		w.unlock()
	}
}

// InstallCapture wraps ctx's current response writer in a CaptureWriter,
// installs it via ctx.SetResponseWriter (backend-agnostic: core re-wraps
// with its tracking writer, gin routes through the facade, echo swaps the
// Response.Writer field), and returns the wrapper. unlock, when non-nil,
// is released by the wrapper's Unlock method — the /token single-flight
// path passes its mutex release; the generic middleware passes nil. This
// is the shared capture step for both paths: the response-capture
// mechanism exists in exactly one place.
func InstallCapture(ctx core.HandlerContext, unlock func()) *CaptureWriter {
	w := &CaptureWriter{ResponseWriter: ctx.ResponseWriter(), unlock: unlock}
	ctx.SetResponseWriter(w)
	return w
}

// ReplayCachedResponse writes a cached idempotency hit back verbatim
// (Content-Type + 200 + body). Shared by the Idempotency middleware hit
// short-circuit and the sso /token hit path.
func ReplayCachedResponse(ctx core.HandlerContext, cached []byte) {
	w := ctx.ResponseWriter()
	w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cached)
}

// CommitCapturedBody caches a captured response body under key when the
// status is 2xx and the body is non-empty — error responses are never
// replayed as successes. The shared commit step for both the middleware
// CommitIdempotentResponse and the sso /token commit path.
func CommitCapturedBody(ctx core.HandlerContext, key string, cache core.IdempotentCache, body []byte, statusCode int) {
	if key == "" || cache == nil {
		return
	}
	if statusCode < 200 || statusCode >= 300 || len(body) == 0 {
		return
	}
	_ = cache.Set(ctx.Request().Context(), key, body, 0)
}

// Idempotency returns a core.MiddlewareFunc that:
//  1. Checks for the Idempotency-Key header
//  2. Replays a cached response at the MIDDLEWARE level and aborts the
//     chain — all three backends skip the handler on a hit
//  3. Wraps the ResponseWriter to capture the response
//  4. Stores key+cache+capture in the request context for
//     CommitIdempotentResponse
//
// ORACLE-SAFE POSITION INVARIANT: a middleware-level replay is only sound
// when this middleware runs AT OR AFTER client authentication — a cached
// success must never be answered to a request that would have failed
// authentication. Install it only at or after the authentication step of
// a chain. The /token endpoint keeps its own post-auth hit check instead
// (sso.beginTokenIdempotency) with its fingerprint-scoped store.
//
// The optional recorder backs the loud commit: when a request that carried
// an Idempotency-Key reaches CommitIdempotentResponse without a capture
// wrapper installed (a regression), the commit fails open — the response
// is unchanged — and records an idempotency_capture_missing audit event
// carrying a sha-256 fingerprint of the key, never the key itself.
func Idempotency(cache core.IdempotentCache, recorders ...*audit.Recorder) core.MiddlewareFunc {
	if cache == nil {
		return func(ctx core.HandlerContext) {}
	}
	var rec *audit.Recorder
	for _, r := range recorders {
		if r != nil {
			rec = r
			break
		}
	}
	return func(ctx core.HandlerContext) {
		r := ctx.Request()
		key := r.Header.Get(core.HeaderIdempotencyKey)
		if key == "" {
			return
		}
		if cached, ok, _ := cache.Get(r.Context(), key); ok && len(cached) > 0 {
			ReplayCachedResponse(ctx, cached)
			ctx.Abort()
			return
		}
		capture := InstallCapture(ctx, nil)
		*r = *r.WithContext(withIdempotencyState(r.Context(), idempotencyState{
			key:     key,
			cache:   cache,
			capture: capture,
			rec:     rec,
		}))
	}
}

// CommitIdempotentResponse caches the captured response after the handler
// returns a 2xx. Call after the handler's ctx.JSON(). The capture wrapper
// is read from the request context (installed by Idempotency) — never
// from a concrete type assertion on ctx.ResponseWriter(), which cannot
// see through the gin facade / echo Response object.
func CommitIdempotentResponse(ctx core.HandlerContext, statusCode int) {
	st, ok := idempotencyStateFromContext(ctx.Request().Context())
	if !ok || st.key == "" || st.cache == nil {
		return
	}
	if statusCode < 200 || statusCode >= 300 {
		return
	}
	if st.capture == nil {
		recordCaptureMissing(ctx, st.key, st.rec)
		return
	}
	CommitCapturedBody(ctx, st.key, st.cache, st.capture.Body(), statusCode)
}

// recordCaptureMissing emits the idempotency_capture_missing audit event:
// a request carried an Idempotency-Key and reached commit with no capture
// wrapper installed. Fail open with audit (AGENTS.md §3): the response is
// unchanged, the degradation is observable. The metadata carries a
// sha-256 prefix of the key — never the raw key — keeping bounded
// cardinality and no secret material in the audit stream.
func recordCaptureMissing(ctx core.HandlerContext, key string, rec *audit.Recorder) {
	if rec == nil {
		return
	}
	e := audit.EventFromRequest(ctx)
	e.Type = audit.EventIdempotencyCaptureMissing
	e.Outcome = audit.OutcomeFailure
	sum := sha256.Sum256([]byte(key))
	audit.SetMeta(e, "idempotency_key_sha256", hex.EncodeToString(sum[:8]))
	rec.Record(ctx.Request().Context(), e)
}
