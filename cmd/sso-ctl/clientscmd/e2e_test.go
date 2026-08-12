package clientscmd

// E-4..E-6: faithful CLI-driving acceptance for the tenant-binding surfacing
// direction. One real deployment (sso.Server + admin gRPC-gateway over the
// SAME store, admin-gated) is driven through the real command paths —
// runGet for `clients get`, and apiclient.CheckRun for the deploy sweep
// `check --expect-tenant-id` — proving the operator can cross-reference the
// registry state against the minted token.
//
// T-C invariant (seed contract): the seeded client MUST include
// "client_credentials" in GrantTypes, or rejectDisallowedGrantType
// (interfaces/sso/server_token.go) returns 400 unauthorized_client and the
// sweep's mint leg fails before any claim is produced.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
	"github.com/yangwb1123/snaplink/domains/permissions"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver/grpcadmin"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// adminValidator accepts the bearer "good" and resolves to user-alice,
// mirroring test/admin_middleware_test.go's stubValidator (test/ cannot be
// imported from cmd/).
type adminValidator struct{}

func (adminValidator) ValidateToken(_ context.Context, token string) (*sso.TokenClaims, error) {
	if token != "good" {
		return nil, errors.New("invalid")
	}
	return &sso.TokenClaims{Subject: "user-alice"}, nil
}

// adminPermsProvider grants user-alice admin:* (mirrors adminProvider in
// test/admin_middleware_test.go).
func adminPermsProvider(t *testing.T) permissions.Provider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	if err := p.AddRole(ctx, "", permissions.Role{Code: "root", Permissions: []string{"admin:*"}}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := p.AssignRoles(ctx, "user-alice", "", []string{"root"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	return p
}

// newCLIDeployment builds the same deployment shape as
// test/client_tenant_binding_test.go: a live sso.Server whose issuer equals
// its listener address, plus the admin gRPC-gateway behind the
// AdminMiddleware. client-1 is bound to tenant-acme and is cc-mintable
// (T-C: GrantTypes includes client_credentials; AllowedScopes non-empty so
// the sweep's T-8d probe scope is never granted).
func newCLIDeployment(t *testing.T) *httptest.Server {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := "http://" + lis.Addr().String()

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "client-1", Secret: "s", Active: true, TokenStrategy: "jwt",
		Name:          "Tenant Acme App",
		AllowedScopes: []string{"openid", "profile"},
		// T-C: client_credentials is mandatory for the sweep mint leg.
		GrantTypes: []string{"client_credentials", "authorization_code", "refresh_token"},
		TenantID:   "tenant-acme",
	})

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(addr),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)
	srv := sso.NewServer(
		sso.WithIssuer(addr),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
	)

	gw := runtime.NewServeMux()
	if err := adminv1.RegisterClientAdminServiceHandlerServer(
		context.Background(), gw,
		grpcadmin.NewClientAdminService(clients, nil, nil, nil),
	); err != nil {
		t.Fatalf("register admin gateway: %v", err)
	}
	mw := sso.NewAdminMiddleware(adminValidator{}, adminPermsProvider(t))
	gated := mw.HTTPMiddleware(gw)

	outer := http.NewServeMux()
	outer.Handle("/api/v1/admin/clients", gated)
	outer.Handle("/api/v1/admin/clients/", gated)
	outer.Handle("/", srv.Handler())

	httpSrv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: outer}}
	httpSrv.Start()
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// captureStdoutAndStderr redirects os.Stdout/os.Stderr for the duration of
// fn and returns both streams (the package's captureStdout covers stdout
// only; E-6 needs the stderr diagnostic).
func captureStdoutAndStderr(t *testing.T, fn func()) (string, string) {
	t.Helper()
	oldOut, oldErr := os.Stdout, os.Stderr
	rOut, wOut, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = wOut, wErr
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	fn()
	_ = wOut.Close()
	_ = wErr.Close()
	out, _ := io.ReadAll(rOut)
	errB, _ := io.ReadAll(rErr)
	return string(out), string(errB)
}

// runCheck drives apiclient.CheckRun with captured streams, returning the
// exit code, stdout, and stderr.
func runCheck(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	code := 0
	out, errB := captureStdoutAndStderr(t, func() { code = apiclient.CheckRun(args) })
	return code, out, errB
}

// TestClientsGet_RendersTenantBindingFromLiveServer is E-4: `clients get`
// against the real deployment renders the gateway's camelCase tenantId
// value for the bound client.
func TestClientsGet_RendersTenantBindingFromLiveServer(t *testing.T) {
	srv := newCLIDeployment(t)
	t.Setenv(apiclient.EnvAddr, srv.URL)
	t.Setenv(apiclient.EnvToken, "good")

	out := captureStdout(t, func() {
		if code := runGet([]string{"client-1"}); code != 0 {
			t.Fatalf("runGet exit code = %d, want 0", code)
		}
	})

	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("runGet output not valid JSON: %v\noutput: %s", err, out)
	}
	tenant, _ := got["tenantId"].(string)
	if tenant != "tenant-acme" {
		t.Errorf("runGet tenantId = %q, want %q\noutput: %s", tenant, "tenant-acme", out)
	}
}

// TestCheck_ExpectTenantIDMatchesRenderedBinding is E-5: the deploy sweep's
// declared tenant (--expect-tenant-id tenant-acme) passes against the same
// client whose binding `clients get` rendered — the cross-reference the
// direction exists to close.
func TestCheck_ExpectTenantIDMatchesRenderedBinding(t *testing.T) {
	srv := newCLIDeployment(t)
	code, out, errB := runCheck(t,
		"--addr", srv.URL,
		"--client-id", "client-1",
		"--client-secret", "s",
		"--expect-tenant-id", "tenant-acme",
	)
	if code != 0 {
		t.Fatalf("CheckRun exit code = %d, want 0\nstdout: %s\nstderr: %s", code, out, errB)
	}
	if !strings.Contains(out, "mint: OK") {
		t.Errorf("stdout missing %q:\n%s", "mint: OK", out)
	}
	if !strings.Contains(out, "check OK") {
		t.Errorf("stdout missing %q:\n%s", "check OK", out)
	}
}

// TestCheck_ExpectTenantIDMismatchFails is E-6: a declaration that
// disagrees with the registry state fails the sweep with the named
// tenant_id diagnostic — the mismatch is visible pre-runtime.
func TestCheck_ExpectTenantIDMismatchFails(t *testing.T) {
	srv := newCLIDeployment(t)
	code, out, errB := runCheck(t,
		"--addr", srv.URL,
		"--client-id", "client-1",
		"--client-secret", "s",
		"--expect-tenant-id", "tenant-other",
	)
	if code != 1 {
		t.Fatalf("CheckRun exit code = %d, want 1\nstdout: %s\nstderr: %s", code, out, errB)
	}
	if !strings.Contains(errB, "claims: tenant_id") {
		t.Errorf("stderr missing tenant_id diagnostic:\n%s", errB)
	}
}
