// Command playground starts a fully-wired demo SSO server and serves a
// single-page, zero-dependency Web UI that lists every feature and lets
// you fire real requests against the live endpoints from the browser.
//
//	go run ./examples/playground            # then open http://localhost:8090
//
// Everything is in-memory and seeded with a demo user (alice / secret),
// a demo client (playground-client / playground-secret), and an
// MFA-required client (mfa-client). Nothing here is production wiring —
// it is a learning / ▶try-it surface. A handful of /playground/* debug
// endpoints (audit log, multi-alg JWKS) are added by THIS command, not
// the SDK, purely so the UI can visualize internal state.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	_ "embed"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/spi"
)

//go:embed index.html
var indexHTML []byte

const (
	demoUser     = "alice"
	demoPassword = "secret"
	demoClient   = "playground-client"
	demoSecret   = "playground-secret"
	mfaClient    = "mfa-client"
	mfaSecret    = "mfa-secret"
)

// demoTOTPSecret is the RFC 6238 §B test secret ("12345678901234567890").
// Hardcoded (and known to the browser) so the playground can compute a
// valid TOTP code for the MFA demo deterministically. NEVER do this in
// production — secrets are per-user and never leave the server.
var demoTOTPSecret = []byte("12345678901234567890")

// mfaForClientScorer forces step-up MFA only for mfaClient, so the
// primary password-login demos stay one-step while the MFA demo has a
// dedicated client to exercise the /auth/mfa leg.
type mfaForClientScorer struct{}

func (mfaForClientScorer) Score(_ context.Context, req *spi.RiskRequest) (*spi.RiskAssessment, error) {
	if req != nil && req.ClientID == mfaClient {
		return &spi.RiskAssessment{Decision: spi.DecisionRequireMFA}, nil
	}
	return &spi.RiskAssessment{Decision: spi.DecisionAllow}, nil
}

func main() {
	listen := flag.String("listen", ":8090", "HTTP listen address")
	flag.Parse()
	ctx := context.Background()
	issuerName := "http://localhost" + *listen

	users := seedUsers(ctx)
	clients := seedClients(issuerName)
	perms := seedPermissions(ctx)
	mfaProvider := buildMFAProvider()

	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(issuerName),
		defaultimpl.WithEd25519TokenTTL(10*time.Minute),
	)
	auditSink := audit.NewMemorySink(500)

	srv := sso.NewServer(buildServerOptions(serverDeps{
		issuerName:  issuerName,
		users:       users,
		clients:     clients,
		perms:       perms,
		mfaProvider: mfaProvider,
		issuer:      issuer,
		auditSink:   auditSink,
	})...)

	root := buildRootHandler(srv.Handler(), auditSink, buildAlgSamples(issuerName))

	banner(*listen, issuerName)
	log.Fatal(http.ListenAndServe(*listen, root))
}

// seedUsers creates the in-memory user provider seeded with the demo user.
func seedUsers(ctx context.Context) *defaultimpl.MemoryUserProvider {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: demoUser, Name: "Alice Example", Email: "alice@example.com"})
	return users
}

// seedClients seeds the demo client and the MFA-required client.
func seedClients(issuerName string) *defaultimpl.MemoryClientStore {
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: demoClient, Secret: demoSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         sso.TokenStrategyJWT,
		AllowedScopes:         []string{"openid", "profile", "email", "offline_access"},
		RedirectURIs:          []string{issuerName + "/callback"},
	})
	clients.AddSeed(&sso.Client{
		ID: mfaClient, Secret: mfaSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         sso.TokenStrategyJWT,
		AllowedScopes:         []string{"openid", "profile"},
		RedirectURIs:          []string{issuerName + "/callback"},
	})
	return clients
}

// buildPasswordAuth wires the demo password verifier.
func buildPasswordAuth() sso.Authenticator {
	return authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, password string) (*sso.AuthResult, error) {
			if username == demoUser && password == demoPassword {
				return &sso.AuthResult{UserID: demoUser, Provider: "password"}, nil
			}
			return nil, errors.New("invalid credentials")
		},
	))
}

// buildMFAProvider enrolls alice with the RFC test secret; the provider
// verifies codes at /auth/mfa.
func buildMFAProvider() spi.MFAProvider {
	totpStore := authenticators.NewMemoryTOTPStore()
	totpStore.Set(demoUser, demoTOTPSecret)
	return authenticators.NewTOTPMFAProvider(authenticators.NewTOTPAuthenticator(totpStore))
}

// seedPermissions assigns alice a role + menu tree, embedded in the login
// response (WithEmbedPermissionsInLogin) and queryable at
// /permissions|roles|menus/me.
func seedPermissions(ctx context.Context) *permissions.MemoryProvider {
	perms := permissions.NewMemoryProvider()
	_ = perms.AddRole(ctx, demoClient, permissions.Role{
		Code: "editor", Name: "Editor",
		Permissions: []string{"doc:read", "doc:write", "menu:dashboard", "menu:docs"},
	})
	_ = perms.SetMenus(ctx, demoClient, permissions.MenuTree{
		{ID: "dashboard", Name: "Dashboard", Path: "/dash", Permission: "menu:dashboard"},
		{ID: "docs", Name: "Documents", Path: "/docs", Permission: "menu:docs", Buttons: []permissions.Button{
			{Code: "new", Name: "New", Permission: "doc:write"},
		}},
		{ID: "admin", Name: "Admin (hidden)", Path: "/admin", Permission: "admin:all"},
	})
	_ = perms.AssignRoles(ctx, demoUser, demoClient, []string{"editor"})
	return perms
}

// serverDeps groups the pre-built collaborators that buildServerOptions wires
// into the playground server.
type serverDeps struct {
	issuerName  string
	users       sso.UserProvider
	clients     sso.ClientStore
	perms       *permissions.MemoryProvider
	mfaProvider spi.MFAProvider
	issuer      *defaultimpl.Ed25519JWTIssuer
	auditSink   *audit.MemorySink
}

// buildServerOptions assembles the full playground option set: core wiring,
// OAuth/OIDC stores, and the opt-in features the UI demonstrates.
func buildServerOptions(d serverDeps) []sso.Option {
	return []sso.Option{
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithIssuer(d.issuerName),
		sso.WithUserProvider(d.users),
		sso.WithClientStore(d.clients),
		sso.WithAuthenticator(buildPasswordAuth()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer(sso.TokenStrategyJWT, d.issuer),
		sso.WithIDTokenIssuer(d.issuer),
		sso.WithDefaultTokenStrategy(sso.TokenStrategyJWT),
		// OAuth/OIDC stores so the matching endpoints are live.
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 10*time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), 24*time.Hour),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), 10*time.Minute, 5*time.Second, ""),
		sso.WithPARStore(defaultimpl.NewMemoryPARStore(), 60*time.Second),
		// Opt-in features the playground demonstrates.
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true}),
		sso.WithPermissionProvider(d.perms),
		sso.WithEmbedPermissionsInLogin(),
		sso.WithJARM(d.issuer),
		sso.WithRiskScorer(mfaForClientScorer{}),
		sso.WithMFAProvider(d.mfaProvider),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 5*time.Minute),
		// FAPI 2.0 in INSPECTION mode: every non-compliant login is
		// recorded as a fapi_compliance_violation (visible in the audit
		// viewer) but never blocked — the ramp-up contract.
		sso.WithFAPIProfile(sso.FAPIModeInspection),
		sso.WithAuditRecorder(audit.New(d.auditSink)),
	}
}

// buildRootHandler routes the playground-only debug endpoints (audit log,
// multi-alg JWKS, static UI) and delegates everything else to the SDK handler.
func buildRootHandler(ssoHandler http.Handler, auditSink *audit.MemorySink, algSamples map[string]any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/", "/playground", "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexHTML)
		case "/playground/audit":
			writeJSON(w, recentAudit(r.Context(), auditSink))
		case "/playground/algs":
			writeJSON(w, algSamples)
		default:
			ssoHandler.ServeHTTP(w, r)
		}
	})
}

// recentAudit returns the most recent audit events (newest first) as a
// trimmed view for the UI. Demo-only — the real audit query path is the
// admin-protected /api/v1/audit API.
func recentAudit(ctx context.Context, sink *audit.MemorySink) []map[string]any {
	events, err := sink.Query(ctx, audit.Query{})
	if err != nil {
		return nil
	}
	out := make([]map[string]any, 0, len(events))
	for i, e := range events {
		if i >= 50 {
			break
		}
		out = append(out, map[string]any{
			"time":     e.Timestamp.Format(time.RFC3339),
			"type":     string(e.Type),
			"outcome":  string(e.Outcome),
			"actor":    e.ActorID,
			"client":   e.ClientID,
			"reason":   e.Reason,
			"metadata": e.Metadata,
		})
	}
	return out
}

// buildAlgSamples constructs one issuer per supported signing alg and
// returns each one's JWKS — so the UI can show that the SDK publishes
// EdDSA / ES256 / RS256 / PS256 keys. Demo-only display helper.
func buildAlgSamples(iss string) map[string]any {
	ed := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(iss))
	es := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAIssuer(iss))
	rs := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAIssuer(iss), defaultimpl.WithRSAAlg("RS256"))
	ps := defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAIssuer(iss), defaultimpl.WithRSAAlg("PS256"))
	ctx := context.Background()
	jwks := func(p interface {
		JWKS(context.Context) ([]sso.JWK, error)
	}) []sso.JWK {
		k, _ := p.JWKS(ctx)
		return k
	}
	return map[string]any{
		"EdDSA": jwks(ed),
		"ES256": jwks(es),
		"RS256": jwks(rs),
		"PS256": jwks(ps),
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func banner(listen, issuer string) {
	url := "http://localhost" + listen
	fmt.Println(strings.Repeat("─", 64))
	fmt.Println("  SSO Playground")
	fmt.Printf("  Open:        %s\n", url)
	fmt.Printf("  Issuer:      %s\n", issuer)
	fmt.Printf("  Demo user:   %s / %s\n", demoUser, demoPassword)
	fmt.Printf("  Demo client: %s / %s\n", demoClient, demoSecret)
	fmt.Printf("  MFA client:  %s / %s  (forces TOTP step-up)\n", mfaClient, mfaSecret)
	fmt.Println(strings.Repeat("─", 64))
}
