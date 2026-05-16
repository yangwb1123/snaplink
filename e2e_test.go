package sso_test

// End-to-end "联动测试" — exercises the full service-to-service path the
// user asked about: a browser-shaped POST /auth/login lands a JWT, then a
// downstream App-shaped GET /items calls back into the SSO server over
// the gRPC wire (JWKS for token validation, Authorizer for Check, AuditWriter
// for Record).
//
// The whole stack runs in-process — no Docker, no real PG — because the
// SSO server is fully memory-backed today. httptest.NewServer is the REST
// wire; bufconn is the gRPC wire. Both go-real-wire (JSON over HTTP, proto
// over HTTP/2) so this catches any breakage that pure in-process unit tests
// would miss.
//
// Pattern intentionally mirrors examples/embedded-app and examples/remote-app:
// the same appcore.Handler that ships with the examples is what the test
// drives. If this E2E test passes, the public quickstart paths work.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/examples/appcore"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ssoclient/remote"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const (
	e2eClient       = "items-app"
	e2eClientSecret = "secret"
	e2eAlice        = "alice"
	e2eAlicePwd     = "s3cret!"
	e2eBob          = "bob"
	e2eBobPwd       = "p4ssw0rd"
	e2eItemsPerm    = "items:read"
)

// e2eHarness bundles the running test infra plus the live audit sink so
// individual tests can assert on emitted events without re-plumbing.
type e2eHarness struct {
	HTTP *httptest.Server // REST + JWKS
	GRPC *grpc.ClientConn // bufconn-backed Authorizer + AuditWriter
	Sink *audit.MemorySink
}

// buildE2E spins up the full sso-server stack in-process and returns a
// harness wired ready for tests. The REST surface (Mount-installed
// handlers + JWKS) is on httptest; the gRPC back-channel is on bufconn.
//
// Both wire to the SAME permission provider and audit recorder, mirroring
// the production deployment where /auth/login (REST) and Authz.Check (gRPC)
// share the same in-memory state inside the sso-server process.
//
// Seed data:
//   - clients: {items-app} accepting password + JWT
//   - users:   {alice, bob}
//   - perms:   alice → items-reader → items:read; bob → nothing
//
// The empty clientID under which we register the role matches the
// audience-less JWT the Ed25519 issuer mints (Subject.Audience is not
// populated by handleLogin) — same trick examples/embedded-app uses.
func buildE2E(t *testing.T) *e2eHarness {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("e2e-sso"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: e2eAlice, Email: "alice@x"})
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: e2eBob, Email: "bob@x"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    e2eClient,
		Secret:                e2eClientSecret,
		Name:                  "Items App",
		AllowedScopes:         []string{"openid"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	// Closure-backed PasswordVerifier covers the two seed users without
	// needing a real password hash — the password contract is "Verify
	// returns AuthResult on match, error on miss".
	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			switch {
			case u == e2eAlice && p == e2eAlicePwd:
				return &sso.AuthResult{UserID: e2eAlice}, nil
			case u == e2eBob && p == e2eBobPwd:
				return &sso.AuthResult{UserID: e2eBob}, nil
			default:
				return nil, errors.New("e2e: bad credentials")
			}
		}),
	)

	prov := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = prov.AddRole(ctx, "", permissions.Role{
		Code:        "items-reader",
		Permissions: []string{e2eItemsPerm},
	})
	_ = prov.AssignRoles(ctx, e2eAlice, "", []string{"items-reader"})

	sink := audit.NewMemorySink(100)
	recorder := audit.New(sink)

	srv := sso.NewServer(
		sso.WithIssuer("e2e-sso"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(prov),
		sso.WithAuditRecorder(recorder),
	)

	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	authzv1.RegisterAuthorizerServer(gs, grpcserver.NewAuthzService(prov))
	auditv1.RegisterAuditWriterServer(gs, grpcserver.NewAuditService(recorder))
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	})

	return &e2eHarness{HTTP: httpServer, GRPC: conn, Sink: sink}
}

// appHandlerFor returns an httptest.Server hosting appcore.Handler with the
// REMOTE ssoclient implementations: JWKS over HTTP for ValidateToken,
// bufconn-backed gRPC for Authz.Check + Audit.Record. This is the App
// side of the 联动 flow — identical to what examples/remote-app does at
// runtime.
func appHandlerFor(t *testing.T, h *e2eHarness) *httptest.Server {
	t.Helper()
	jwks := remote.NewJWKSCache(h.HTTP.URL + "/.well-known/jwks.json")
	handler := &appcore.Handler{
		Auth:  remote.NewAuthClient(jwks),
		Authz: remote.NewAuthzClient(h.GRPC),
		Audit: remote.NewAuditClient(h.GRPC),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/items", handler.ListItems)
	app := httptest.NewServer(mux)
	t.Cleanup(func() {
		app.Close()
		jwks.Close()
	})
	return app
}

// loginAs drives POST /auth/login against the harness REST surface and
// returns the access_token from the response. Fails the test on any
// non-200 — the negative cases below test denial AFTER login, not at
// the login step itself.
func loginAs(t *testing.T, h *e2eHarness, username, password string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  e2eClient,
		"credential": map[string]string{"username": username, "password": password},
	})
	resp, err := http.Post(h.HTTP.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login(%s) = %d body=%s", username, resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("login response missing access_token: %v", out)
	}
	return tok
}

// getItems is the request-side of the App handler call. Returns the
// raw response so individual tests can assert on status + body.
func getItems(t *testing.T, app *httptest.Server, bearer string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, app.URL+"/items", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /items: %v", err)
	}
	return resp
}

// hasAuditEvent reports whether the sink recorded an event of the given
// type + outcome (since events also carry reason/actor we let those vary).
// Snapshot via Query{} pulls everything in the ring.
func hasAuditEvent(t *testing.T, sink *audit.MemorySink, typ audit.EventType, outcome audit.Outcome) bool {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{Type: typ, Outcome: outcome})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	return len(events) > 0
}

// TestE2E_LoginThenAuthorizeAcrossWire exercises the full 联动 path:
// browser-shaped POST /auth/login over HTTP → JWT bearer → App-shaped
// GET /items that calls back into the SSO server over the gRPC wire for
// ValidateToken (via JWKS), Authz.Check, and Audit.Record.
//
// Asserts: 200 + items in the body + the audit recorder captured the
// items_list success event AND the login success event.
func TestE2E_LoginThenAuthorizeAcrossWire(t *testing.T) {
	h := buildE2E(t)
	app := appHandlerFor(t, h)

	tok := loginAs(t, h, e2eAlice, e2eAlicePwd)

	resp := getItems(t, app, tok)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /items = %d body=%s", resp.StatusCode, raw)
	}
	var out struct {
		Items []string `json:"items"`
		User  string   `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode items: %v", err)
	}
	if len(out.Items) == 0 || out.User != e2eAlice {
		t.Errorf("items response = %+v want non-empty items + user=%s", out, e2eAlice)
	}

	if !hasAuditEvent(t, h.Sink, "items_list", audit.OutcomeSuccess) {
		t.Errorf("expected items_list success in audit sink, got none")
	}
	if !hasAuditEvent(t, h.Sink, audit.EventLogin, audit.OutcomeSuccess) {
		t.Errorf("expected login success in audit sink, got none")
	}
}

// TestE2E_DeniedWhenSubjectLacksPermission verifies authorization
// enforces across the wire: bob logs in fine but lacks items:read, so
// GET /items returns 403 and a denial audit event lands.
func TestE2E_DeniedWhenSubjectLacksPermission(t *testing.T) {
	h := buildE2E(t)
	app := appHandlerFor(t, h)

	tok := loginAs(t, h, e2eBob, e2eBobPwd)

	resp := getItems(t, app, tok)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET /items for bob = %d body=%s want 403", resp.StatusCode, raw)
	}
	if !hasAuditEvent(t, h.Sink, "items_list", audit.OutcomeFailure) {
		t.Errorf("expected items_list failure in audit sink, got none")
	}
}

// TestE2E_NoTokenIsUnauthorized is the sanity guard on the App handler:
// hitting /items with no bearer at all must return 401. Cheap insurance
// that the appcore wiring isn't accidentally allow-all.
func TestE2E_NoTokenIsUnauthorized(t *testing.T) {
	h := buildE2E(t)
	app := appHandlerFor(t, h)

	resp := getItems(t, app, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /items no-bearer = %d want 401", resp.StatusCode)
	}
}

// TestE2E_BadCredentialsRejected confirms the password authenticator
// path declines an unknown user via the public REST surface (returns
// 401, not a 500).
func TestE2E_BadCredentialsRejected(t *testing.T) {
	h := buildE2E(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  e2eClient,
		"credential": map[string]string{"username": "ghost", "password": "x"},
	})
	resp, err := http.Post(h.HTTP.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad login = %d, want 401", resp.StatusCode)
	}
}
