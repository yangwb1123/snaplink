package ssotest

// T-8a: a target deployment in exactly the shape `sso-ctl legacy-sync
// --apply` produces (client row tenant-bound, imported user with a bcrypt
// credential) mints an access token carrying tenant_id exactly once with
// the bound value. The exactly-once pin is the RAW payload key count —
// a decoded-map assertion alone would silently last-win on duplicate keys
// (json.Unmarshal into map[string]any) if claimsWithoutEmittedKeys ever
// regressed.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	legacySyncClientID = "lsync-web"
	legacySyncUserID   = "alice"
	legacySyncPassword = "correct horse battery staple"
	legacySyncTenant   = "tenant-acme"
)

// newLegacySyncDeployment wires a target SQLite deployment in the exact
// shape legacy-sync --apply produces: the clients row comes from the REAL
// sqlite clients table (tenant_id='tenant-acme', password authenticator
// allowed, jwt strategy, active), the imported user's credential from the
// real sqlite password_credentials table (bcrypt via SetPassword), plus
// MemoryUserProvider (user id == username), the password authenticator and
// an Ed25519 JWT issuer — the same production wiring a real deployment
// uses, not mocks.
func newLegacySyncDeployment(t *testing.T) *httptest.Server {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &sso.User{ID: legacySyncUserID}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	clients, err := sqlitestores.NewClientStore(memDSN("legacysync_" + t.Name()))
	if err != nil {
		t.Fatalf("NewClientStore: %v", err)
	}
	t.Cleanup(func() { _ = clients.Close() })
	if err := clients.Put(ctx, &sso.Client{
		ID:                    legacySyncClientID,
		Secret:                "s",
		Name:                  "Legacy Sync App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
		TenantID:              legacySyncTenant,
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	creds, err := sqlitestores.NewPasswordCredentialStore(memDSN("legacysync_creds_" + t.Name()))
	if err != nil {
		t.Fatalf("NewPasswordCredentialStore: %v", err)
	}
	t.Cleanup(func() { _ = creds.Close() })
	if err := creds.SetPassword(ctx, legacySyncUserID, legacySyncPassword); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	// Identity resolver: this deployment's login username IS the userID —
	// the "simplest deployments" case, same as legacy-sync's imported users
	// (provider sv_sso, login id == user id in the user provider).
	resolve := func(_ context.Context, username string) (string, error) { return username, nil }
	pw := authenticators.NewPasswordAuthenticator(authenticators.NewStoredPasswordVerifier(creds, resolve))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPasswordCredentialStore(creds),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// loginLegacySync drives POST /auth/login for the harness's imported user
// and returns the status code plus decoded JSON body.
func loginLegacySync(t *testing.T, hs *httptest.Server) (int, map[string]any) {
	t.Helper()
	return postJSON(t, hs, "/auth/login", map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  legacySyncClientID,
		"credential": map[string]string{"username": legacySyncUserID, "password": legacySyncPassword},
	})
}

// jwtRawPayload returns the base64url-decoded JWT segment 1 (the claim
// set) as raw JSON text — the input the exactly-once key-count assertion
// needs (jwtAllClaims only returns the decoded map, which last-wins on
// duplicate keys).
func jwtRawPayload(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	return string(raw)
}

// TestLegacySyncDeploymentMintsTenantClaimExactlyOnce pins the T-8a
// positive leg: the minted token carries the bound tenant_id exactly once.
func TestLegacySyncDeploymentMintsTenantClaimExactlyOnce(t *testing.T) {
	t.Parallel()
	hs := newLegacySyncDeployment(t)
	status, body := loginLegacySync(t, hs)
	if status != http.StatusOK {
		t.Fatalf("login status = %d body=%v", status, body)
	}
	token, _ := body["access_token"].(string)
	if token == "" {
		t.Fatalf("no access_token in response: %v", body)
	}
	raw := jwtRawPayload(t, token)
	// Structural exactly-once pin: in decoded JSON text, `"tenant_id":`
	// can only occur as a genuine tenant_id key (values escape embedded
	// quotes; sibling keys like x_tenant_id lack the leading quote).
	if got := strings.Count(raw, `"tenant_id":`); got != 1 {
		t.Fatalf("tenant_id appears %d times in payload %s", got, raw)
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got, _ := claims["tenant_id"].(string); got != legacySyncTenant {
		t.Fatalf("tenant_id = %q, want %q (payload %s)", got, legacySyncTenant, raw)
	}
}
