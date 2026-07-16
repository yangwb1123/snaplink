// Package admin holds the bearer-gated admin HTTP middleware + gRPC
// interceptor that protects /api/v1/admin/*, /api/v1/audit/*, and
// /api/v1/netpolicy/policies*. Both transport variants share one
// AdminMiddleware construction object so the scope rules can't drift
// between them.
package admin

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/admingovernance"
	"github.com/snaplink/sso/shared/core"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Scope is the wildcard permission code that grants both read and write
// access to every admin RPC. The wildcard matcher (Matches) handles `admin:*`
// → admin:read / admin:write expansion.
const (
	Scope      = "admin:*"
	ScopeRead  = "admin:read"
	ScopeWrite = "admin:write"
)

// TokenValidator is the minimal contract the admin middleware needs:
// a way to validate a bearer token and recover the subject's identity.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*core.TokenClaims, error)
}

// Authorizer answers "is this subject allowed this admin scope?". The
// stock implementation queries a permissions.Provider; alternative
// implementations could read from an external policy engine (OPA, Rego).
type Authorizer interface {
	HasAdminScope(ctx context.Context, userID, clientID, requiredScope string) (bool, error)
}

// providerAuthorizer adapts a permissions.Provider to Authorizer.
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

// Middleware is the construction object: shared between the HTTP
// middleware and the gRPC interceptor. Both check the same bearer token and
// require the same scope per (transport, method) tuple.
//
// methodScopes maps a fully-qualified gRPC method ("/snaplink.admin.v1.UserAdminService/Delete")
// or an HTTP path prefix to the required scope. The default policy is:
//   - GET / non-mutating  → admin:read
//   - everything else     → admin:write
//
// When a recorder is wired (via SetAuditRecorder), the UnaryServerInterceptor
// records an audit Event for every gated RPC (method, actor, duration, status).
type Middleware struct {
	validator    TokenValidator
	authorizer   Authorizer
	methodScopes map[string]string // optional override
	// rateLimitStore, when set (SetRateLimit / SetRateLimitPolicyStore),
	// gates the admin surface as one shared bucket (adminRateLimitKey);
	// nil = unlimited. See governance.go for both setters + checkRateLimit.
	rateLimitStore *ratelimit.PolicyStore
	recorder     *audit.Recorder   // when set, every gRPC admin RPC is audited

	// adminTokenStore tracks token metadata for idle-timeout enforcement.
	// When set, every protected HTTP request updates LastUsedAt (Touch).
	adminTokenStore core.AdminTokenStore

	// sessionTTL is the idle timeout for admin bearer tokens. 0 = no timeout.
	sessionTTL time.Duration

	// quota / ipPolicy / destructive are the admin governance framework's
	// transport-level checks (see governance.go): a per-tenant/admin write
	// QUOTA (distinct from rateLimitStore's token-bucket rate), an optional
	// IP-allowlist/geo-lock, and a destructive-action confirmation guard.
	// All nil/empty by default — byte-identical to a build without them.
	quota       *adminQuotaConfig
	ipPolicy    *adminIPPolicy
	destructive admingovernance.DestructiveSet
}

// NewMiddleware wires a Server (the validator) and a permissions.Provider
// (the authorizer) into one admin gate. Either argument may be nil — the
// middleware then rejects every call with FailedPrecondition / 503.
func NewMiddleware(v TokenValidator, prov permissions.Provider) *Middleware {
	return &Middleware{
		validator:    v,
		authorizer:   providerAuthorizer{Prov: prov},
		methodScopes: defaultMethodScopes(),
	}
}

// SetMethodScope overrides the required scope for one gRPC method or HTTP path.
func (a *Middleware) SetMethodScope(methodOrPath, scope string) {
	if a.methodScopes == nil {
		a.methodScopes = map[string]string{}
	}
	a.methodScopes[methodOrPath] = scope
}

// SetAdminTokenStore wires a store for admin bearer token metadata.
// When set, the HTTP middleware calls Touch() on every successful
// request to track last-used-at for idle-timeout enforcement.
func (a *Middleware) SetAdminTokenStore(store core.AdminTokenStore) {
	a.adminTokenStore = store
}

// SetAdminSessionTTL sets the idle timeout for admin bearer tokens.
// 0 disables idle timeout (default). Requires SetAdminTokenStore.
func (a *Middleware) SetAdminSessionTTL(ttl time.Duration) {
	a.sessionTTL = ttl
}

// SetAuditRecorder wires an audit recorder that logs every gRPC admin RPC
// (method, actor, duration, gRPC status code). The interceptor uses it to
// emit an EventAdminGRPCCalled event for observability and compliance.
// When recorder is nil, auditing is disabled (default).
func (a *Middleware) SetAuditRecorder(r *audit.Recorder) {
	a.recorder = r
}

// scopeForGRPC returns the required scope for a fully-qualified gRPC method.
func (a *Middleware) scopeForGRPC(method string) string {
	if s, ok := a.methodScopes[method]; ok {
		return s
	}
	last := method
	if i := strings.LastIndex(method, "/"); i >= 0 {
		last = method[i+1:]
	}
	if isReadMethod(last) {
		return ScopeRead
	}
	return ScopeWrite
}

// scopeForHTTP returns the required scope for an HTTP request: a
// SetMethodScope path-prefix override wins when one matches (see
// methodScopeForPath in governance.go — e.g. an admin debug endpoint that
// must accept a POST body yet is read-only); otherwise GET/HEAD/OPTIONS
// need read and everything else needs write.
func (a *Middleware) scopeForHTTP(r *http.Request) string {
	if scope, ok := a.methodScopeForPath(r.URL.Path); ok {
		return scope
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return ScopeRead
	default:
		return ScopeWrite
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

func defaultMethodScopes() map[string]string {
	return map[string]string{}
}

// isGatedGRPCMethod reports whether a fully-qualified gRPC method requires admin
// authentication. It MIRRORS the HTTP IsProtectedPath set: the admin CRUD
// services, the audit writer, and the netpolicy management service. The gRPC
// netpolicy Classify is included because it is an external management/diagnostic
// API (the same one HTTP gates at /api/v1/netpolicy/classify) — the mesh data
// plane uses the IN-PROCESS classifier and the authz Check RPC, never this
// service. The authz Authorizer (ext-authz data plane + subject permission
// queries) is intentionally open on both transports. Discovery read operations
// (Discover, Watch) are also open — service discovery clients query those without
// admin tokens. Discovery write mutations (Register, Deregister) are gated by
// exact method match because they modify the live service registry; a prefix gate
// would block the open read operations on the same service. Gating by service
// prefix is fail-safe for admin/audit/netpolicy: any future method added under
// those services is gated by default.
func isGatedGRPCMethod(fullMethod string) bool {
	switch fullMethod {
	case "/snaplink.discovery.v1.Discovery/Register",
		"/snaplink.discovery.v1.Discovery/Deregister":
		return true
	}
	return strings.HasPrefix(fullMethod, "/snaplink.admin.v1.") ||
		strings.HasPrefix(fullMethod, "/snaplink.audit.v1.") ||
		strings.HasPrefix(fullMethod, "/snaplink.netpolicy.v1.")
}

// authorizeGRPC runs the bearer + admin-scope gate for a gated gRPC method and
// returns an actor-augmented context. Mirrors HTTPMiddleware's body so the two
// transports enforce identical authentication + scope.
func (a *Middleware) authorizeGRPC(ctx context.Context, fullMethod string) (context.Context, error) {
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
	ok, err := a.authorizer.HasAdminScope(ctx, claims.Subject, clientID, a.scopeForGRPC(fullMethod))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "scope check: %v", err)
	}
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "admin scope required")
	}
	return withActor(ctx, claims.Subject, clientID), nil
}

// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor that gates every
// admin/audit/netpolicy RPC (mirroring the HTTP edge) and, when a recorder is
// wired, records an audit event for every gated call (method, actor, status).
// Other RPCs (authz, discovery) pass through untouched.
func (a *Middleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !isGatedGRPCMethod(info.FullMethod) {
			return handler(ctx, req)
		}
		actorCtx, err := a.authorizeGRPC(ctx, info.FullMethod)
		if err != nil {
			if a.recorder != nil {
				a.recorder.Record(ctx, &audit.Event{
					Type:      audit.EventAdminGRPCCalled,
					Outcome:   audit.OutcomeFailure,
					Reason:    info.FullMethod + ": denied",
					Timestamp: time.Now(),
				})
			}
			return nil, err
		}
		start := time.Now()
		resp, err := handler(actorCtx, req)
		dur := time.Since(start)
		if a.recorder != nil {
			actorID, _, _ := ActorFromContext(actorCtx)
			outcome := audit.OutcomeSuccess
			if err != nil {
				outcome = audit.OutcomeFailure
			}
			a.recorder.Record(ctx, &audit.Event{
				Type:      audit.EventAdminGRPCCalled,
				ActorID:   actorID,
				Outcome:   outcome,
				Reason:    info.FullMethod,
				Metadata:  map[string]string{"duration": dur.String()},
				Timestamp: time.Now(),
			})
		}
		return resp, err
	}
}

// StreamServerInterceptor gates streaming RPCs with the same policy as the unary
// interceptor — notably audit.v1.AuditWriter/StreamEvents (bulk event ingestion,
// i.e. event forgery if open) and netpolicy.v1.PolicyService/Watch, which the
// unary interceptor cannot cover.
func (a *Middleware) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !isGatedGRPCMethod(info.FullMethod) {
			return handler(srv, ss)
		}
		ctx, err := a.authorizeGRPC(ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &actorServerStream{ServerStream: ss, ctx: ctx})
	}
}

// actorServerStream overrides Context() so a gated streaming handler observes
// the actor-augmented context produced by authorizeGRPC.
type actorServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *actorServerStream) Context() context.Context { return s.ctx }

// HTTPMiddleware wraps an http.Handler and gates every request whose path
// is under /api/v1/admin/. Other paths pass through.
func (a *Middleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !IsProtectedPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// IP-allowlist/geo-lock runs BEFORE anything else: a disallowed
		// network must never reach rate-limiting or auth machinery (no
		// oracle — the response is identical regardless of what a valid
		// token would have done).
		if !checkIPPolicy(w, r, a.ipPolicy) {
			return
		}
		if !checkRateLimit(w, a.rateLimitStore) {
			return
		}
		if !checkDestructiveConfirm(w, r, a.destructive) {
			return
		}
		claims, clientID, ok := a.authenticateHTTP(w, r)
		if !ok {
			return
		}

		// Admin session idle-timeout enforcement + token-touch.
		if a.enforceIdleTimeout(w, r, claims) {
			return
		}
		if !checkWriteQuota(w, r, a.quota, claims.Subject, tenantHintFromClaims(claims)) {
			return
		}

		next.ServeHTTP(w, r.WithContext(withActor(r.Context(), claims.Subject, clientID)))
	})
}

// authenticateHTTP validates the bearer token and admin scope for r, writing
// the appropriate 401/403/500/503 response and returning ok=false on any
// failure. Split out of HTTPMiddleware to stay under the function-length
// budget.
func (a *Middleware) authenticateHTTP(w http.ResponseWriter, r *http.Request) (claims *core.TokenClaims, clientID string, ok bool) {
	if a.validator == nil || a.authorizer == nil {
		http.Error(w, `{"error":"admin_auth_not_configured"}`, http.StatusServiceUnavailable)
		return nil, "", false
	}
	token := bearerFromHTTP(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="admin"`)
		http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
		return nil, "", false
	}
	claims, err := a.validator.ValidateToken(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="admin", error="invalid_token"`)
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
		return nil, "", false
	}
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	allowed, err := a.authorizer.HasAdminScope(r.Context(), claims.Subject, clientID, a.scopeForHTTP(r))
	if err != nil {
		http.Error(w, `{"error":"internal_error"}`, http.StatusInternalServerError)
		return nil, "", false
	}
	if !allowed {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return nil, "", false
	}
	return claims, clientID, true
}

// enforceIdleTimeout checks the admin bearer token's last-used-at against
// the configured session TTL. When the token has been idle longer than the
// TTL it writes a 401 session_expired response and returns true (the caller
// must return immediately). On success (or when idle timeout is not configured)
// it updates LastUsedAt via Touch and returns false so the request proceeds.
func (a *Middleware) enforceIdleTimeout(w http.ResponseWriter, r *http.Request, claims *core.TokenClaims) bool {
	if a.sessionTTL <= 0 || a.adminTokenStore == nil || claims.JTI == "" {
		return false
	}
	meta, err := a.adminTokenStore.GetByID(r.Context(), claims.JTI)
	if err == nil && !meta.LastUsedAt.IsZero() && time.Since(meta.LastUsedAt) > a.sessionTTL {
		w.Header().Set("WWW-Authenticate", `Bearer realm="admin", error="invalid_token", error_description="session expired"`)
		http.Error(w, `{"error":"session_expired"}`, http.StatusUnauthorized)
		return true
	}
	_ = a.adminTokenStore.Touch(r.Context(), claims.JTI)
	return false
}

func bearerFromHTTP(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// IsProtectedPath returns true when path requires an admin-scope
// bearer. Covers:
//   - /api/v1/admin/*       — admin CRUD + audit-RPC gateway
//   - /api/v1/compliance/*  — GDPR subject export/erase (PII leak + data
//     destruction across stores)
//   - /api/v1/scim/*        — SCIM 2.0 provisioning over the whole user
//     directory (RFC 7644)
//   - /api/v1/audit/*       — event query API exposes subject IDs,
//     IPs, geo, outcomes for every login attempt; PII-grade leak if open
//   - /api/v1/netpolicy/policies* — list / get / apply / delete
//     network classification topology
//   - /api/v1/netpolicy/classify  — debug endpoint that resolves any
//     IP against the current topology
//
// /api/v1/netpolicy/resolve-me stays open: it's the client-facing
// "what network am I from" lookup, no privileged data leaves the
// server (just the caller's own classification).
func IsProtectedPath(path string) bool {
	switch {
	case strings.HasPrefix(path, "/api/v1/admin/"):
		return true
	case strings.HasPrefix(path, "/api/v1/compliance/"):
		// GDPR subject export/erase: leaks (export) and destroys (erase)
		// a subject's data across stores — admin-only, never open.
		return true
	case strings.HasPrefix(path, "/api/v1/scim/"):
		// SCIM 2.0 provisioning (RFC 7644): lists, replaces, and deletes
		// the entire user directory — same admin-only threat model as the
		// compliance + admin CRUD surfaces, never open.
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
	auths := md.Get("authorization")
	if len(auths) == 0 {
		return ""
	}
	auth := auths[0]
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

type actorContextKey struct{}

// ActorFromContext extracts the validated admin actor stamped by
// the admin middleware. Returns ok=false when the context did not
// pass through the middleware (non-admin endpoint, OR mis-wiring).
func ActorFromContext(ctx context.Context) (userID, clientID string, ok bool) {
	a, _ := ctx.Value(actorContextKey{}).([2]string)
	if a[0] == "" {
		return "", "", false
	}
	return a[0], a[1], true
}

func withActor(ctx context.Context, userID, clientID string) context.Context {
	return context.WithValue(ctx, actorContextKey{}, [2]string{userID, clientID})
}
