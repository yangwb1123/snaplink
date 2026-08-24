package middleware

// Always-on structured access logging (design
// docs/design/middleware-observability-unified.md, Decisions 1-6): one
// fixed-field INFO record per request, with body capture as an explicit
// per-deployment policy. interfaces/middleware is at its 10-file ceiling,
// so AccessLogger/BodyLogPolicy/redaction live in this file (request_log.go)
// instead of a new accesslog.go — the design's capture stack replaces the
// old DEBUG RequestLogger + requestLogResponseWriter that lived here.

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const (
	// accessLogMessage is the fixed message of the always-on access record.
	accessLogMessage = "access"
	// defaultBodyLogMaxBytes caps captured request/response body fields
	// when BodyLogPolicy.MaxBodyBytes is zero.
	defaultBodyLogMaxBytes int64 = 4096
	// bodyLogRedactionLiteral is the exact replacement for redacted
	// credential values. No length-preserving padding: padding is a side
	// channel for short secrets like TOTP codes.
	bodyLogRedactionLiteral = "[redacted]"
)

// bodyLogSecretKeys is the exact-match (case-insensitive) redaction
// vocabulary for captured bodies, derived from shared/core's credential
// naming and the grant surfaces. Any key CONTAINING one of the substrings
// in bodyLogSecretKeySubstrings is redacted even when not listed here —
// over-redaction is the safe failure mode (a leak is not).
var bodyLogSecretKeys = []string{
	"password", "new_password", "current_password",
	"client_secret", "secret", "api_key", "apikey",
	"code", "authorization_code", "device_code", "otp", "totp",
	"mfa_code", "verification_code", "backup_code", "recovery_code", "answer",
	"token", "access_token", "refresh_token", "id_token", "id_token_hint",
	"assertion", "credential",
}

// bodyLogSecretKeySubstrings is the over-redaction heuristic applied to
// every key: a future endpoint that names a credential field
// my_mfa_code cannot silently leak through the exact vocabulary.
var bodyLogSecretKeySubstrings = []string{"secret", "password", "token", "assertion", "code"}

// isBodyLogSecretKey reports whether a body key carries credential-shaped
// values and must be redacted (exact match, then substring heuristic).
func isBodyLogSecretKey(key string) bool {
	lower := strings.ToLower(key)
	for _, k := range bodyLogSecretKeys {
		if lower == k {
			return true
		}
	}
	for _, sub := range bodyLogSecretKeySubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// BodyLogPolicy controls OPTIONAL request/response body capture inside
// AccessLogger. The zero value disables body capture entirely — the
// default, and the only shape that makes credentials structurally
// impossible to log. Capturing bodies is a deliberate per-deployment
// debugging posture, not a log level: it requires an allowlist (or the
// deprecated AllowAllPaths escape hatch), an explicit SampleRate > 0,
// and is bounded by MaxBodyBytes and the redaction vocabulary above.
type BodyLogPolicy struct {
	// Paths is the allowlist of exact paths whose bodies may be captured.
	// Empty means no path is eligible (default). When populated it takes
	// precedence over AllowAllPaths.
	Paths []string
	// AllowAllPaths bypasses the allowlist. Deprecated escape hatch;
	// reproduces the old logBodies=true semantics — logging every body on
	// every path is a credential-exposure posture. Never combine with a
	// populated Paths.
	AllowAllPaths bool
	// SampleRate is the fraction (0.0-1.0) of eligible requests whose
	// bodies are captured. 0 (default) means bodies are never captured;
	// body capture only exists when an operator explicitly sets > 0.
	SampleRate float64
	// MaxBodyBytes caps each captured body field (request and response).
	// 0 selects the default of 4096.
	MaxBodyBytes int64
}

// EnabledFor reports whether bodies may be captured for this path. The
// allowlist wins when populated; AllowAllPaths applies only to an empty
// allowlist (the deprecated escape hatch).
func (p BodyLogPolicy) EnabledFor(path string) bool {
	if len(p.Paths) > 0 {
		for _, pth := range p.Paths {
			if pth == path {
				return true
			}
		}
		return false
	}
	return p.AllowAllPaths
}

// maxBodyBytes resolves the effective capture cap (default when unset).
func (p BodyLogPolicy) maxBodyBytes() int64 {
	if p.MaxBodyBytes > 0 {
		return p.MaxBodyBytes
	}
	return defaultBodyLogMaxBytes
}

// samplePasses is the per-request Bernoulli decision for body capture,
// evaluated once, before the body is read. SampleRate 0 can never pass;
// >= 1.0 always passes. Sampling applies to body capture only — the
// fixed access-log fields are never sampled.
func (p BodyLogPolicy) samplePasses() bool {
	return p.SampleRate >= 1.0 || rand.Float64() < p.SampleRate
}

// accessLogResponseWriter captures the response status code and, when
// capture is enabled, the response body up to the policy cap (bytes past
// the cap pass through untouched — never buffers unboundedly, never holds
// the response hostage). Unwrap lets http.ResponseController reach the
// underlying transport writer so streaming endpoints keep working under
// the access logger.
type accessLogResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
	body        *cappedBodyBuffer
}

func (w *accessLogResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.statusCode = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *accessLogResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.statusCode = http.StatusOK
		w.wroteHeader = true
	}
	if w.body != nil {
		w.body.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying writer so http.NewResponseController /
// http.ResponseController can reach Flusher/Hijacker/ReaderFrom on the
// real transport writer through the middleware wrapper.
func (w *accessLogResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// cappedBodyBuffer captures up to cap bytes of a body field and discards
// the rest. Write always reports the full length so a caller never sees
// a short write for a truncated capture.
type cappedBodyBuffer struct {
	buf []byte
	cap int64
}

func (b *cappedBodyBuffer) Write(p []byte) (int, error) {
	remaining := b.cap - int64(len(b.buf))
	if remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		b.buf = append(b.buf, p[:n]...)
	}
	return len(p), nil
}

// AccessLogger returns an http.Handler middleware that emits exactly one
// INFO record per request with a fixed, low-cardinality field set:
//
//	method, path, status, duration_ms, client_ip, request_id, trace_id
//
// It is the always-on access log; BodyLogPolicy controls only the OPTIONAL
// body capture (zero value = never capture bodies). The fixed fields are
// never sampled. path is r.URL.Path only — query strings can carry
// code/token credentials and are structurally excluded. client_ip is the
// canonical peertrust result (validated real IP under trustedProxies;
// legacy first-hop fallback otherwise). request_id/trace_id come from the
// request header and context respectively — populated by the
// tracing/correlation middleware when installed, empty otherwise.
//
// The record is new output only: no response, header, or audit behavior
// changes. duration_ms is wall-clock since middleware entry, including
// rate-limit wait, so it matches operator intuition for a slow request.
func AccessLogger(l spi.Logger, policy BodyLogPolicy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			capture := policy.EnabledFor(r.URL.Path) && policy.samplePasses()

			rlw := &accessLogResponseWriter{ResponseWriter: w}
			var reqBody []byte
			if capture {
				rlw.body = &cappedBodyBuffer{cap: policy.maxBodyBytes()}
				reqBody = captureRequestBody(r, policy.maxBodyBytes())
			}

			next.ServeHTTP(rlw, r)
			emitAccessRecord(l, rlw, r, start, capture, reqBody)
		})
	}
}

// captureRequestBody reads at most max+1 bytes of the request body and
// restores the FULL original body for downstream handlers: the unread
// remainder stays readable, so the body-limit middleware and handlers see
// a byte-identical body. Returns nil (body untouched) when the read fails.
func captureRequestBody(r *http.Request, max int64) []byte {
	if r.Body == nil {
		return nil
	}
	limited := io.LimitReader(r.Body, max+1)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
	return b
}

// emitAccessRecord assembles and logs the one INFO access record for a
// request. status defaults to 200 when the handler never called
// WriteHeader; body fields appear only when capture was allowed and the
// buffers hold bytes, redacted by content type.
func emitAccessRecord(l spi.Logger, rlw *accessLogResponseWriter, r *http.Request, start time.Time, capture bool, reqBody []byte) {
	status := rlw.statusCode
	if status == 0 {
		// Handler never called WriteHeader: net/http's implicit
		// 200 is the documented default.
		status = http.StatusOK
	}
	fields := []any{
		"method", r.Method,
		"path", r.URL.Path,
		"status", status,
		"duration_ms", time.Since(start).Milliseconds(),
		"client_ip", peertrust.ClientIP(r),
		"request_id", r.Header.Get(core.HeaderRequestID),
		"trace_id", core.TraceIDFromContext(r.Context()),
	}
	if capture {
		if len(reqBody) > 0 {
			fields = append(fields, "request_body", redactBody(r.Header.Get("Content-Type"), reqBody))
		}
		if len(rlw.body.buf) > 0 {
			fields = append(fields, "response_body", redactBody(rlw.Header().Get("Content-Type"), rlw.body.buf))
		}
	}
	l.Info(accessLogMessage, fields...)
}

// redactBody rewrites a captured body so credential-shaped values cannot
// reach the log record. Parsed and rewritten by content type; any other
// content type (or a malformed body) passes through capped raw bytes —
// a debugging aid that cannot widen the leak (the cap still applies, and
// the allowlist still gates entry).
func redactBody(contentType string, body []byte) string {
	switch {
	case strings.HasPrefix(strings.ToLower(contentType), "application/json"):
		return redactJSONBody(body)
	case strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded"):
		return redactFormBody(body)
	default:
		return string(body)
	}
}

// redactFormBody parses, redacts secret keys, and re-encodes a
// form-urlencoded body. A malformed body passes through raw.
func redactFormBody(body []byte) string {
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return string(body)
	}
	redacted := false
	for k := range vals {
		if isBodyLogSecretKey(k) {
			vals.Set(k, bodyLogRedactionLiteral)
			redacted = true
		}
	}
	if !redacted {
		return string(body)
	}
	return vals.Encode()
}

// redactJSONBody decodes, walks (objects at any depth, including inside
// arrays), redacts secret keys, and re-encodes a JSON body. Unknown keys
// survive. A malformed body passes through raw.
func redactJSONBody(body []byte) string {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return string(body)
	}
	redactBodyValue(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		return string(body)
	}
	return string(out)
}

// redactBodyValue recursively replaces values under secret keys with the
// redaction literal.
func redactBodyValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if isBodyLogSecretKey(k) {
				t[k] = bodyLogRedactionLiteral
			} else {
				redactBodyValue(val)
			}
		}
	case []any:
		for _, item := range t {
			redactBodyValue(item)
		}
	}
}
