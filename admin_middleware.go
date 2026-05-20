package sso

import (
	"context"
	"net/http"
	"strings"

	"github.com/snaplink/sso/permissions"
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
		if !strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
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
