package sso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/spi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AdminScope is the wildcard permission code that grants both read and write
// access to every admin RPC. The wildcard matcher (Matches) handles `admin:*`
// → admin:read / admin:write expansion.
const (
	AdminScope      = "admin:*"
	AdminScopeRead  = "admin:read"
	AdminScopeWrite = "admin:write"
)

// AdminTokenValidator is the minimal contract the admin middleware needs:
// a way to validate a bearer token and recover the subject's identity.
type AdminTokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*TokenClaims, error)
}

// AdminAuthorizer answers "is this subject allowed this admin scope?". The
// stock implementation queries a permissions.Provider; alternative
// implementations could read from an external policy engine (OPA, Rego).
type AdminAuthorizer interface {
	HasAdminScope(ctx context.Context, userID, clientID, requiredScope string) (bool, error)
}

// providerAuthorizer adapts a permissions.Provider to AdminAuthorizer.
// admin:* matches admin:read AND admin:write thanks to the wildcard matcher.
type providerAuthorizer struct{ Prov permissions.Provider }

func (p providerAuthorizer) HasAdminScope(ctx context.Context, userID, clientID, requiredScope string) (bool, error) {
	if p.Prov == nil {
		return false, nil
	}
	perms, err := p.Prov.Permissions(ctx, userID, clientID)
	if err != nil {
		return false, err
	}
	return permissions.Matches(perms, requiredScope), nil
}

// AdminMiddleware is the construction object: shared between the HTTP
// middleware and the gRPC interceptor. Both check the same bearer token and
// require the same scope per (transport, method) tuple.
//
// methodScopes maps a fully-qualified gRPC method ("/snaplink.admin.v1.UserAdminService/Delete")
// or an HTTP path prefix to the required scope. The default policy is:
//   - GET / non-mutating  → admin:read
//   - everything else     → admin:write
type AdminMiddleware struct {
	validator    AdminTokenValidator
	authorizer   AdminAuthorizer
	methodScopes map[string]string // optional override
}

// NewAdminMiddleware wires a Server (the validator) and a permissions.Provider
// (the authorizer) into one admin gate. Either argument may be nil — the
// middleware then rejects every call with FailedPrecondition / 503.
func NewAdminMiddleware(v AdminTokenValidator, prov permissions.Provider) *AdminMiddleware {
	return &AdminMiddleware{
		validator:    v,
		authorizer:   providerAuthorizer{Prov: prov},
		methodScopes: defaultAdminMethodScopes(),
	}
}

// SetMethodScope overrides the required scope for one gRPC method or HTTP path.
func (a *AdminMiddleware) SetMethodScope(methodOrPath, scope string) {
	if a.methodScopes == nil {
		a.methodScopes = map[string]string{}
	}
	a.methodScopes[methodOrPath] = scope
}

// scopeForGRPC returns the required scope for a fully-qualified gRPC method
// like "/snaplink.admin.v1.UserAdminService/Delete".
func (a *AdminMiddleware) scopeForGRPC(method string) string {
	if s, ok := a.methodScopes[method]; ok {
		return s
	}
	// Method-name suffix tells us mutate vs read.
	last := method
	if i := strings.LastIndex(method, "/"); i >= 0 {
		last = method[i+1:]
	}
	if isReadMethod(last) {
		return AdminScopeRead
	}
	return AdminScopeWrite
}

// scopeForHTTP returns the required scope for an HTTP request based on its
// method. GET/HEAD/OPTIONS need read; everything else needs write.
func (a *AdminMiddleware) scopeForHTTP(r *http.Request) string {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return AdminScopeRead
	default:
		return AdminScopeWrite
	}
}

func isReadMethod(name string) bool {
	switch {
	case strings.HasPrefix(name, "List"),
		strings.HasPrefix(name, "Get"),
		strings.HasPrefix(name, "Search"),
		strings.HasPrefix(name, "Find"):
		return true
	}
	return false
}

// defaultAdminMethodScopes lets callers opt specific RPCs into a non-default
// scope. Currently empty — the prefix heuristic above covers the standard
// CRUD pattern.
func defaultAdminMethodScopes() map[string]string {
	return map[string]string{}
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that gates
// every admin RPC. Non-admin RPCs (audit/authz/discovery/netpolicy) pass
// through untouched — the interceptor only triggers on methods under
// "/snaplink.admin.v1.".
func (a *AdminMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !strings.HasPrefix(info.FullMethod, "/snaplink.admin.v1.") {
			return handler(ctx, req)
		}
		if a.validator == nil || a.authorizer == nil {
			return nil, status.Error(codes.FailedPrecondition, "admin auth not configured")
		}
		token := bearerFromMetadata(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing bearer token")
		}
		claims, err := a.validator.ValidateToken(ctx, token)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token: %v", err)
		}
		clientID := ""
		if len(claims.Audience) > 0 {
			clientID = claims.Audience[0]
		}
		ok, err := a.authorizer.HasAdminScope(ctx, claims.Subject, clientID, a.scopeForGRPC(info.FullMethod))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "scope check: %v", err)
		}
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "admin scope required")
		}
		// Stash the actor so downstream methods can attribute audit events.
		ctx = withAdminActor(ctx, claims.Subject, clientID)
		return handler(ctx, req)
	}
}

// HTTPMiddleware wraps an http.Handler and gates every request whose path
// is under /api/v1/admin/. Other paths pass through.
func (a *AdminMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isAdminProtectedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if a.validator == nil || a.authorizer == nil {
			http.Error(w, `{"error":"admin_auth_not_configured"}`, http.StatusServiceUnavailable)
			return
		}
		token := bearerFromHTTP(r)
		if token == "" {
			// RFC 6750 §3.1: no credentials presented → challenge
			// without an error parameter so the RP knows the
			// resource expects Bearer auth.
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
			http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
			return
		}
		claims, err := a.validator.ValidateToken(r.Context(), token)
		if err != nil {
			// RFC 6750 §3.1: token validation failure → carry the
			// invalid_token error code so the RP can distinguish
			// "refresh and retry" from "missing credentials".
			w.Header().Set("WWW-Authenticate", `Bearer realm="admin", error="invalid_token"`)
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}
		clientID := ""
		if len(claims.Audience) > 0 {
			clientID = claims.Audience[0]
		}
		ok, err := a.authorizer.HasAdminScope(r.Context(), claims.Subject, clientID, a.scopeForHTTP(r))
		if err != nil {
			http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r.WithContext(withAdminActor(r.Context(), claims.Subject, clientID)))
	})
}

func bearerFromHTTP(r *http.Request) string {
	h := r.Header.Get(HeaderAuthorization)
	if !strings.HasPrefix(h, BearerPrefix) {
		return ""
	}
	return strings.TrimPrefix(h, BearerPrefix)
}

// isAdminProtectedPath returns true when path requires an admin-scope
// bearer. Covers:
//   - /api/v1/admin/*       — admin CRUD + audit-RPC gateway
//   - /api/v1/audit/*       — event query API exposes subject IDs,
//     IPs, geo, outcomes for every login
//     attempt; PII-grade leak if open
//   - /api/v1/netpolicy/policies* — list / get / apply / delete
//     network classification topology
//   - /api/v1/netpolicy/classify  — debug endpoint that resolves any
//     IP against the current topology
//
// /api/v1/netpolicy/resolve-me stays open: it's the client-facing
// "what network am I from" lookup, no privileged data leaves the
// server (just the caller's own classification).
func isAdminProtectedPath(path string) bool {
	switch {
	case strings.HasPrefix(path, "/api/v1/admin/"):
		return true
	case strings.HasPrefix(path, "/api/v1/audit/"):
		return true
	case path == "/api/v1/netpolicy/classify",
		strings.HasPrefix(path, "/api/v1/netpolicy/policies"):
		return true
	}
	return false
}

func bearerFromMetadata(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	if vals := md.Get("authorization"); len(vals) > 0 {
		v := vals[0]
		if rest, ok := strings.CutPrefix(v, BearerPrefix); ok {
			return rest
		}
		return v
	}
	return ""
}

// adminActorContextKey mirrors grpcserver.AdminActorContextKey but lives in
// the sso package to avoid a cyclic import. The two are interoperable
// because grpcserver.recordAdmin reads the same value from this same key.
type adminActorContextKey struct{}

// AdminActorFromContext returns the userID + clientID stashed by the admin
// middleware, when present.
func AdminActorFromContext(ctx context.Context) (userID, clientID string, ok bool) {
	v, _ := ctx.Value(adminActorContextKey{}).([2]string)
	if v == ([2]string{}) {
		return "", "", false
	}
	return v[0], v[1], true
}

func withAdminActor(ctx context.Context, userID, clientID string) context.Context {
	return context.WithValue(ctx, adminActorContextKey{}, [2]string{userID, clientID})
}

// type assertion + nil guard in one place.
const GeoHandlerContextKey = "geo:info"

// DefaultGeoLookupTimeout caps how long a single geo lookup may
// block in the request hot path. Geo is a UX hint, not a
// request-blocking concern — keep this short.
const DefaultGeoLookupTimeout = 200 * time.Millisecond

// GeoIPExtractor pulls a client IP from a request. Implementations
// may trust forwarded headers (when there's a known edge proxy)
// or stick to RemoteAddr (when the SSO server faces the internet
// directly). Returning nil tells the middleware to skip the
// lookup for this request.
type GeoIPExtractor func(r *http.Request) net.IP

// GeoMiddlewareOptions tune the geo middleware. Zero value is fine
// — the middleware uses sane defaults (DefaultGeoIPExtractor +
// DefaultGeoLookupTimeout, no error reporter).
type GeoMiddlewareOptions struct {
	// Extractor pulls the client IP. Defaults to DefaultGeoIPExtractor
	// (XFF first hop → X-Real-IP → RemoteAddr host).
	Extractor GeoIPExtractor
	// Timeout caps a single Lookup. Defaults to DefaultGeoLookupTimeout.
	Timeout time.Duration
	// OnError is called when Lookup fails with anything other than
	// geo.ErrNotFound / geo.ErrInvalidIP. Optional — geo failures are
	// intentionally non-fatal so the request continues either way,
	// but operators may want to log + alert on backend outages.
	OnError func(err error)
}

// GeoMiddleware constructs a MiddlewareFunc that looks up the
// request's client IP via p and stashes the resulting *GeoInfo on
// the HandlerContext value bag (key GeoHandlerContextKey). Lookup
// failure (including ErrNotFound) is intentionally non-fatal: the
// request continues with no GeoInfo set.
//
// A nil Provider returns a no-op middleware so callers can wire
// this unconditionally and let configuration decide whether to
// enable geo at all.
func GeoMiddleware(p geo.Provider, opts GeoMiddlewareOptions) MiddlewareFunc {
	if p == nil {
		return func(HandlerContext) {}
	}
	extract := opts.Extractor
	if extract == nil {
		extract = DefaultGeoIPExtractor
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultGeoLookupTimeout
	}
	return func(hctx HandlerContext) {
		ip := extract(hctx.Request())
		if ip == nil {
			return
		}
		ctx, cancel := context.WithTimeout(hctx.Request().Context(), timeout)
		defer cancel()
		info, err := p.Lookup(ctx, ip)
		if err != nil {
			if opts.OnError != nil && err != geo.ErrNotFound && err != geo.ErrInvalidIP {
				opts.OnError(err)
			}
			return
		}
		hctx.Set(GeoHandlerContextKey, info)
	}
}

// GeoFromHandlerContext returns the *GeoInfo the geo middleware
// stashed for this request, or (nil, false) when the lookup didn't
// run / failed / wasn't wired. Callers should treat the false case
// as "no hint, fall through to defaults".
func GeoFromHandlerContext(hctx HandlerContext) (*geo.GeoInfo, bool) {
	if hctx == nil {
		return nil, false
	}
	v := hctx.Get(GeoHandlerContextKey)
	if v == nil {
		return nil, false
	}
	info, ok := v.(*geo.GeoInfo)
	return info, ok && info != nil
}

// DefaultGeoIPExtractor pulls the client IP in priority order:
//  1. X-Forwarded-For first hop (the originating client per RFC
//     7239 conventions; later hops are intermediate proxies).
//  2. X-Real-IP (single value; some edge proxies use this instead).
//  3. RemoteAddr host part (the direct TCP peer; correct only when
//     the server faces the internet directly).
//
// Returns nil when no usable address is found. SECURITY: trusting
// XFF/X-Real-IP is correct ONLY when a known edge proxy strips
// and re-sets the header. Internet-facing deployments without an
// edge proxy should write a custom GeoIPExtractor that ignores
// forwarded headers and uses RemoteAddr only.
func DefaultGeoIPExtractor(r *http.Request) net.IP {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip
		}
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
			return ip
		}
	}
	if r.RemoteAddr != "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			if ip := net.ParseIP(host); ip != nil {
				return ip
			}
		}
		// RemoteAddr without a port (rare: certain test harnesses).
		if ip := net.ParseIP(r.RemoteAddr); ip != nil {
			return ip
		}
	}
	return nil
}

// AuthMiddleware validates Bearer tokens on protected routes.
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
