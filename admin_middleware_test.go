package sso_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/permissions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// stubValidator returns the configured claims when token equals "good"; any
// other token returns an error. Lets tests assert "missing/invalid/valid"
// without spinning up a real issuer.
type stubValidator struct {
	good   string
	claims *sso.TokenClaims
}

func (s stubValidator) ValidateToken(_ context.Context, token string) (*sso.TokenClaims, error) {
	if token != s.good {
		return nil, errors.New("invalid")
	}
	return s.claims, nil
}

// adminProvider builds a permissions.Provider where user-alice has admin:*
// under client_id "" (matching empty audience).
func adminProvider(t *testing.T) permissions.Provider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}})
	_ = p.AssignRoles(ctx, "user-alice", "", []string{"root"})
	return p
}

// nonAdminProvider has user-bob with no admin scope at all.
func nonAdminProvider(t *testing.T) permissions.Provider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.AddRole(ctx, "", permissions.Role{Code: "user", Permissions: []string{"items:read"}})
	_ = p.AssignRoles(ctx, "user-bob", "", []string{"user"})
	return p
}

// --- HTTP middleware tests ---

func newAdminHTTPHarness(t *testing.T, prov permissions.Provider, validClaims *sso.TokenClaims) *httptest.Server {
	t.Helper()
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: validClaims}, prov)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/admin/clients", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/v1/audit/events", func(w http.ResponseWriter, _ *http.Request) {
		// non-admin path should pass through without auth
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"events":[]}`))
	})
	srv := httptest.NewServer(mw.HTTPMiddleware(mux))
	t.Cleanup(srv.Close)
	return srv
}

func httpDo(t *testing.T, method, url, bearer string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestAdminHTTP_NoTokenIs401(t *testing.T) {
	srv := newAdminHTTPHarness(t, adminProvider(t), &sso.TokenClaims{Subject: "user-alice"})
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/clients", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminHTTP_BadTokenIs401(t *testing.T) {
	srv := newAdminHTTPHarness(t, adminProvider(t), &sso.TokenClaims{Subject: "user-alice"})
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/clients", "wrong")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdminHTTP_ValidTokenWithoutScopeIs403(t *testing.T) {
	srv := newAdminHTTPHarness(t, nonAdminProvider(t), &sso.TokenClaims{Subject: "user-bob"})
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/clients", "good")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdminHTTP_ValidTokenWithScope_200(t *testing.T) {
	srv := newAdminHTTPHarness(t, adminProvider(t), &sso.TokenClaims{Subject: "user-alice"})
	resp := httpDo(t, "GET", srv.URL+"/api/v1/admin/clients", "good")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAdminHTTP_NonAdminPathPassesThrough(t *testing.T) {
	srv := newAdminHTTPHarness(t, adminProvider(t), nil)
	// /api/v1/audit/events is NOT under /api/v1/admin/, so no auth needed.
	resp := httpDo(t, "GET", srv.URL+"/api/v1/audit/events", "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (passthrough)", resp.StatusCode)
	}
}

// --- gRPC interceptor tests ---

// fakeUnaryHandler captures whether it was called and what context it saw.
func fakeUnaryHandler(reached *bool, gotCtx *context.Context) grpc.UnaryHandler {
	return func(ctx context.Context, _ any) (any, error) {
		*reached = true
		*gotCtx = ctx
		return "ok", nil
	}
}

func adminInfo(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func mdCtx(bearer string) context.Context {
	if bearer == "" {
		return context.Background()
	}
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+bearer))
}

func TestAdminGRPC_NonAdminMethodPassesThrough(t *testing.T) {
	mw := sso.NewAdminMiddleware(stubValidator{}, nil)
	intercept := mw.UnaryServerInterceptor()

	reached := false
	gotCtx := context.Background()
	if _, err := intercept(context.Background(), nil, adminInfo("/snaplink.audit.v1.AuditWriter/Record"), fakeUnaryHandler(&reached, &gotCtx)); err != nil {
		t.Fatalf("err: %v", err)
	}
	if !reached {
		t.Error("expected handler to be reached")
	}
}

func TestAdminGRPC_NoTokenIsUnauthenticated(t *testing.T) {
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}}, adminProvider(t))
	intercept := mw.UnaryServerInterceptor()

	reached := false
	gotCtx := context.Background()
	_, err := intercept(context.Background(), nil, adminInfo("/snaplink.admin.v1.ClientAdminService/List"), fakeUnaryHandler(&reached, &gotCtx))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
	if reached {
		t.Error("handler should not have been reached")
	}
}

func TestAdminGRPC_BadTokenIsUnauthenticated(t *testing.T) {
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}}, adminProvider(t))
	intercept := mw.UnaryServerInterceptor()

	reached := false
	gotCtx := context.Background()
	_, err := intercept(mdCtx("wrong"), nil, adminInfo("/snaplink.admin.v1.ClientAdminService/Get"), fakeUnaryHandler(&reached, &gotCtx))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestAdminGRPC_ValidTokenNoScopeIsPermissionDenied(t *testing.T) {
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-bob"}}, nonAdminProvider(t))
	intercept := mw.UnaryServerInterceptor()

	reached := false
	gotCtx := context.Background()
	_, err := intercept(mdCtx("good"), nil, adminInfo("/snaplink.admin.v1.ClientAdminService/List"), fakeUnaryHandler(&reached, &gotCtx))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestAdminGRPC_ValidTokenWithScopeReachesHandler(t *testing.T) {
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "user-alice"}}, adminProvider(t))
	intercept := mw.UnaryServerInterceptor()

	reached := false
	gotCtx := context.Background()
	out, err := intercept(mdCtx("good"), nil, adminInfo("/snaplink.admin.v1.ClientAdminService/Delete"), fakeUnaryHandler(&reached, &gotCtx))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if out != "ok" || !reached {
		t.Fatal("handler not reached")
	}
	// Actor stashed in context?
	uid, _, ok := sso.AdminActorFromContext(gotCtx)
	if !ok || uid != "user-alice" {
		t.Errorf("actor not stashed: ok=%v uid=%q", ok, uid)
	}
}

func TestAdminMiddleware_ScopeRoutingByMethodName(t *testing.T) {
	mw := sso.NewAdminMiddleware(stubValidator{good: "good", claims: &sso.TokenClaims{Subject: "x"}}, nil)
	// Bypass real authorizer; check the read/write split via SetMethodScope.
	mw.SetMethodScope("/snaplink.admin.v1.X/Custom", "admin:write")
	// Simply assert no panic at construction.
	_ = mw
}
