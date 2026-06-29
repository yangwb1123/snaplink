package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/interfaces/ssoclient"
	"github.com/snaplink/sso/interfaces/ssoclient/remote"
	"github.com/snaplink/sso/shared/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// --- shared no-mock fixtures (reused by auth_test.go) ---

// bufconnAuthz stands up the real Authorizer over an in-memory gRPC server and
// returns a connected *remote.AuthzClient. Mirrors interfaces/ssoclient/remote/grpc_test.go.
func bufconnAuthz(t *testing.T) *remote.AuthzClient {
	t.Helper()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	must(t, p.AddRole(ctx, "web-app", permissions.Role{Code: "admin", Permissions: []string{"user:*"}}))
	must(t, p.SetMenus(ctx, "web-app", permissions.MenuTree{
		{ID: "m-users", Permission: "user:read"},
		{ID: "m-audit", Permission: "audit:read"},
	}))
	must(t, p.AssignRoles(ctx, "user-alice", "web-app", []string{"admin"}))

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	authzv1.RegisterAuthorizerServer(srv, grpcserver.NewAuthzService(p))
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	must(t, err)
	t.Cleanup(func() { _ = conn.Close(); srv.Stop(); _ = lis.Close() })
	return remote.NewAuthzClient(conn)
}

// edIssuer + jwksAuthClient give a real token-mint + real JWKS validation path.
// Mirrors interfaces/ssoclient/remote/auth_multialg_test.go.
func edIssuer() interface {
	Issue(context.Context, *sso.Subject, []string) (*sso.Token, error)
	JWKS(context.Context) ([]core.JWK, error)
} {
	return defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))
}

func jwksAuthClient(t *testing.T, iss interface {
	JWKS(context.Context) ([]core.JWK, error)
}) *remote.AuthClient {
	t.Helper()
	keys, err := iss.JWKS(context.Background())
	must(t, err)
	body, err := json.Marshal(map[string]any{"keys": keys})
	must(t, err)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	cache := remote.NewJWKSCache(srv.URL+"/.well-known/jwks.json", remote.WithJWKSRefreshInterval(time.Hour))
	t.Cleanup(cache.Close)
	return remote.NewAuthClient(cache)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
}

func sliceContains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}

// --- tool tests ---

func TestCheckPermission(t *testing.T) {
	t.Parallel()
	d := &toolDeps{authz: bufconnAuthz(t)}
	_, out, err := d.checkPermission(context.Background(), nil, checkIn{
		SubjectID: "user-alice", ClientID: "web-app", Permission: "user:read",
	})
	if err != nil || !out.Allowed {
		t.Fatalf("want allowed; out=%+v err=%v", out, err)
	}
	_, out2, err2 := d.checkPermission(context.Background(), nil, checkIn{
		SubjectID: "user-alice", ClientID: "web-app", Permission: "audit:read",
	})
	if err2 != nil {
		t.Fatalf("deny-path Check errored: %v", err2)
	}
	if out2.Allowed {
		t.Fatal("want denied for audit:read")
	}
}

func TestListPermissionsAndRoles(t *testing.T) {
	t.Parallel()
	d := &toolDeps{authz: bufconnAuthz(t)}
	_, p, err := d.listPermissions(context.Background(), nil, subjectClientIn{"user-alice", "web-app"})
	if err != nil || len(p.Permissions) != 1 || p.Permissions[0].Code != "user:*" {
		t.Fatalf("perms=%+v err=%v", p, err)
	}
	_, r, err := d.listRoles(context.Background(), nil, subjectClientIn{"user-alice", "web-app"})
	if err != nil || len(r.Roles) != 1 || r.Roles[0].Code != "admin" {
		t.Fatalf("roles=%+v err=%v", r, err)
	}
}

func TestGetMenusFiltered(t *testing.T) {
	t.Parallel()
	d := &toolDeps{authz: bufconnAuthz(t)}
	_, m, err := d.getMenus(context.Background(), nil, subjectClientIn{"user-alice", "web-app"})
	if err != nil || len(m.Menus) != 1 || m.Menus[0].ID != "m-users" {
		t.Fatalf("menus=%+v err=%v", m, err)
	}
}

func TestIntrospectToken(t *testing.T) {
	t.Parallel()
	iss := edIssuer()
	d := &toolDeps{intro: jwksAuthClient(t, iss)}
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "user-1", ClientID: "web-app"}, []string{"mcp:read"})
	must(t, err)

	_, out, err := d.introspectToken(context.Background(), nil, introspectIn{Token: tok.AccessToken})
	if err != nil || !out.Active || out.Subject != "user-1" {
		t.Fatalf("introspect=%+v err=%v", out, err)
	}
	if !sliceContains(out.Scopes, "mcp:read") {
		t.Errorf("want Scopes to contain %q; got %v", "mcp:read", out.Scopes)
	}
	if out.ExpiresAt <= 0 {
		t.Errorf("want ExpiresAt > 0; got %d", out.ExpiresAt)
	}
	if out.ClientID != "web-app" {
		t.Errorf("want ClientID=%q; got %q", "web-app", out.ClientID)
	}
	_, bad, _ := d.introspectToken(context.Background(), nil, introspectIn{Token: "not.a.jwt"})
	if bad.Active {
		t.Fatal("invalid token must be inactive")
	}
}

func TestToMenuDTOs_Nesting(t *testing.T) {
	t.Parallel()
	tree := ssoclient.MenuTree{
		{ID: "root", Name: "Root", Children: []ssoclient.MenuItem{
			{ID: "child", Name: "Child", Permission: "x:read"},
		}},
	}
	out := toMenuDTOs(tree)
	if len(out) != 1 || out[0].ID != "root" || len(out[0].Children) != 1 {
		t.Fatalf("nesting lost: %+v", out)
	}
	child, ok := out[0].Children[0].(menuDTO)
	if !ok || child.ID != "child" {
		t.Fatalf("child not a menuDTO with ID=child: %+v", out[0].Children[0])
	}
}
