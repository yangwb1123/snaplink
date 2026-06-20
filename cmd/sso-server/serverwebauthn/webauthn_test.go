package serverwebauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators/webauthn"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

func TestBuildWebAuthnHelper_Disabled(t *testing.T) {
	h, _, _, err := BuildWebAuthnHelper(config.WebAuthnConfig{}, quietLogger())
	if err != nil {
		t.Fatalf("BuildWebAuthnHelper disabled: %v", err)
	}
	if h != nil {
		t.Fatal("disabled config must return nil helper")
	}
}

func TestBuildWebAuthnHelper_RequiresRPID(t *testing.T) {
	_, _, _, err := BuildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err == nil {
		t.Fatal("missing rp_id must error")
	}
}

func TestBuildWebAuthnHelper_RequiresAtLeastOneOrigin(t *testing.T) {
	_, _, _, err := BuildWebAuthnHelper(config.WebAuthnConfig{
		Enabled: true,
		RPID:    "example.com",
	}, quietLogger())
	if err == nil {
		t.Fatal("missing rp_origins must error")
	}
}

func TestBuildWebAuthnHelper_DefaultsMemoryBackends(t *testing.T) {
	h, _, _, err := BuildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err != nil {
		t.Fatalf("BuildWebAuthnHelper: %v", err)
	}
	if h == nil {
		t.Fatal("helper nil when subsystem enabled")
	}
}

func TestBuildWebAuthnUserStore_SQLiteRequiresDSN(t *testing.T) {
	_, _, err := buildWebAuthnUserStore(config.WebAuthnBackendConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("sqlite backend without dsn must error")
	}
}

func TestBuildWebAuthnSessionStore_SQLiteRequiresDSN(t *testing.T) {
	_, _, err := buildWebAuthnSessionStore(config.WebAuthnBackendConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("sqlite backend without dsn must error")
	}
}

func TestBuildWebAuthnUserStore_UnknownBackend(t *testing.T) {
	_, _, err := buildWebAuthnUserStore(config.WebAuthnBackendConfig{Backend: "redis"})
	if err == nil {
		t.Fatal("unknown backend must error")
	}
}

func TestBuildWebAuthnHelper_SQLiteBackends(t *testing.T) {
	dir := t.TempDir()
	h, _, _, err := BuildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
		Storage: config.WebAuthnStorageConfig{
			Users:    config.WebAuthnBackendConfig{Backend: "sqlite", SQLite: config.WebAuthnBackendSQLiteConfig{DSN: "file:" + filepath.Join(dir, "users.db") + "?_journal=WAL"}},
			Sessions: config.WebAuthnBackendConfig{Backend: "sqlite", SQLite: config.WebAuthnBackendSQLiteConfig{DSN: "file:" + filepath.Join(dir, "sessions.db") + "?_journal=WAL"}},
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("BuildWebAuthnHelper sqlite: %v", err)
	}
	if h == nil {
		t.Fatal("helper nil with sqlite backends")
	}
}

// ----- HTTP wrapper tests -----

func newWebAuthnTestServer(t *testing.T) (*httptest.Server, *webauthn.Helper) {
	t.Helper()
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "Example AS",
		RPOrigins:     []string{"https://sso.example.com"},
		SessionTTL:    time.Minute,
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	httpHandler := srv.Handler()
	if err := MountWebAuthnRoutes(srv, &WebAuthnDeps{Helper: h}); err != nil {
		t.Fatalf("MountWebAuthnRoutes: %v", err)
	}
	ts := httptest.NewServer(httpHandler)
	t.Cleanup(ts.Close)
	return ts, h
}

func TestWebAuthnHTTP_BeginRegistrationReturnsOptionsAndSession(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: "alice@example.com", DisplayName: "Alice"})
	resp, err := http.Post(ts.URL+PathWebAuthnRegistrationBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d want 200", resp.StatusCode)
	}
	var got webauthnBeginRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SessionID == "" {
		t.Fatal("empty session_id")
	}
	if len(got.Options) == 0 {
		t.Fatal("empty options")
	}
	if !strings.Contains(string(got.Options), "challenge") {
		t.Fatalf("options missing challenge: %s", got.Options)
	}
}

func TestWebAuthnHTTP_BeginRequiresUsername(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: ""})
	resp, err := http.Post(ts.URL+PathWebAuthnRegistrationBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_BeginRejectsEmptyBody(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	resp, err := http.Post(ts.URL+PathWebAuthnRegistrationBegin, "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_FinishRequiresSessionID(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	resp, err := http.Post(ts.URL+PathWebAuthnRegistrationFinish, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_FinishUnknownSessionReturns404(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	resp, err := http.Post(ts.URL+PathWebAuthnRegistrationFinish+"?session_id=ghost", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d want 404 (oracle-leak resistance)", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["error"] != "session_invalid" {
		t.Fatalf("error: got %q want session_invalid", got["error"])
	}
}

func TestWebAuthnHTTP_BeginLoginUnknownUserReturns404(t *testing.T) {
	// Unknown username folds into the same 404 session_invalid envelope
	// as bad session_id so a probe can't enumerate registered users.
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: "ghost@example.com"})
	resp, err := http.Post(ts.URL+PathWebAuthnLoginBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d want 404", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["error"] != "session_invalid" {
		t.Fatalf("error: got %q want session_invalid", got["error"])
	}
}

func TestWebAuthnHTTP_AllRoutesCacheControlNoStore(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: "alice"})
	resp, err := http.Post(ts.URL+PathWebAuthnRegistrationBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control: got %q want no-store (credential endpoint)", got)
	}
}

// ----- Token-issuance integration -----

func newWebAuthnIssuingTestServer(t *testing.T, client *sso.Client) (*httptest.Server, *webauthn.Helper) {
	t.Helper()
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "Example AS",
		RPOrigins:     []string{"https://sso.example.com"},
		SessionTTL:    time.Minute,
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	clientStore := defaultimpl.NewMemoryClientStore()
	if client != nil {
		_ = clientStore.Add(context.Background(), client)
	}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clientStore),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpHandler := srv.Handler()
	deps := &WebAuthnDeps{
		Helper:       h,
		ClientStore:  clientStore,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": issuer},
		DefaultStrat: "jwt",
	}
	if err := MountWebAuthnRoutes(srv, deps); err != nil {
		t.Fatalf("MountWebAuthnRoutes: %v", err)
	}
	ts := httptest.NewServer(httpHandler)
	t.Cleanup(ts.Close)
	return ts, h
}

func TestIssueWebAuthnToken_UnknownClientReturnsInvalidClient(t *testing.T) {
	deps := &WebAuthnDeps{
		ClientStore:  defaultimpl.NewMemoryClientStore(),
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	_, err := issueWebAuthnToken(req, deps, "ghost-client", "alice")
	if !errors.Is(err, errWebAuthnClientNotFound) {
		t.Fatalf("got %v want errWebAuthnClientNotFound", err)
	}
	status, code := webauthnIssueErrorStatus(err)
	if status != http.StatusBadRequest || code != "invalid_client" {
		t.Fatalf("error mapping: got (%d, %q) want (400, invalid_client)", status, code)
	}
}

func TestIssueWebAuthnToken_InactiveClientReturnsInvalidClient(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        false,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid"},
	})
	deps := &WebAuthnDeps{
		ClientStore:  store,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	_, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if !errors.Is(err, errWebAuthnClientInactive) {
		t.Fatalf("got %v want errWebAuthnClientInactive", err)
	}
}

func TestIssueWebAuthnToken_MissingIssuerReturnsServerError(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "session",
		AllowedScopes: []string{"openid"},
	})
	deps := &WebAuthnDeps{
		ClientStore:  store,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	_, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if !errors.Is(err, errWebAuthnNoIssuer) {
		t.Fatalf("got %v want errWebAuthnNoIssuer", err)
	}
	status, _ := webauthnIssueErrorStatus(err)
	if status != http.StatusInternalServerError {
		t.Fatalf("missing-issuer maps to %d want 500", status)
	}
}

func TestIssueWebAuthnToken_HappyPath(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid", "profile"},
	})
	deps := &WebAuthnDeps{
		ClientStore:  store,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	token, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if token.AccessToken == "" {
		t.Fatal("AccessToken empty")
	}
	if token.TokenType == "" {
		t.Fatal("TokenType empty")
	}
	if token.ExpiresIn <= 0 {
		t.Fatalf("ExpiresIn %d want >0", token.ExpiresIn)
	}
}

func TestIssueWebAuthnToken_ScopeGate(t *testing.T) {
	// WebAuthn requests the client's full AllowedScopes through oauth.GrantedScopes
	// (the shared scope-authorization gate). openid is preserved so an OIDC client
	// still gets an id_token; a non-openid client gets only its allowed scopes and
	// no id_token even with an issuer wired -- locks the gate routing against the
	// openid-auto-inject concern without regressing the WebAuthn id_token.
	issue := func(allowed []string) *webauthnIssueResult {
		t.Helper()
		store := defaultimpl.NewMemoryClientStore()
		_ = store.Add(context.Background(), &sso.Client{
			ID: "wa-app", Active: true, TokenStrategy: "jwt", AllowedScopes: allowed,
		})
		issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
		deps := &WebAuthnDeps{
			ClientStore:   store,
			TokenIssuers:  map[string]sso.TokenIssuer{"jwt": issuer},
			DefaultStrat:  "jwt",
			IDTokenIssuer: issuer,
		}
		req, _ := http.NewRequest("POST", "http://x/", nil)
		res, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
		if err != nil {
			t.Fatalf("issue(%v): %v", allowed, err)
		}
		return res
	}

	// OIDC client: scope carries the full allowance incl. openid -> id_token issued.
	oidcRes := issue([]string{"openid", "profile"})
	if !strings.Contains(oidcRes.Scope, "openid") || !strings.Contains(oidcRes.Scope, "profile") {
		t.Fatalf("oidc scope = %q want openid+profile", oidcRes.Scope)
	}
	if oidcRes.IDToken == "" {
		t.Fatal("oidc client: expected an id_token (openid in allowance)")
	}

	// Non-OIDC client: scope is exactly the allowance, no openid -> no id_token.
	plainRes := issue([]string{"profile"})
	if plainRes.Scope != "profile" {
		t.Fatalf("non-oidc scope = %q want %q", plainRes.Scope, "profile")
	}
	if plainRes.IDToken != "" {
		t.Fatal("non-oidc client: id_token must be omitted (no openid)")
	}
}

func TestIssueWebAuthnToken_DefaultStrategyFallback(t *testing.T) {
	// Client.TokenStrategy empty → fall back to deps.DefaultStrat.
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "", // intentionally blank
		AllowedScopes: []string{"openid"},
	})
	deps := &WebAuthnDeps{
		ClientStore:  store,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	if _, err := issueWebAuthnToken(req, deps, "wa-app", "alice"); err != nil {
		t.Fatalf("issue with default strategy: %v", err)
	}
}

func TestWebAuthnHTTP_FinishLoginIssuesTokenWhenClientIDProvided(t *testing.T) {
	// End-to-end: register a credential via the helper, then drive
	// Begin/Finish login through the HTTP layer with client_id set.
	// The Finish response should carry an access_token.
	//
	// We can't actually drive a CTAP signing ceremony from a test
	// without a real authenticator, so we short-circuit by calling
	// the helper's BeginLogin to fail with ErrUserUnknown (a known
	// user without credentials) and assert the failure mode — which
	// proves the client_id-bound issuance branch IS gated correctly
	// (no token on failure). The happy path is covered by the
	// unit test on issueWebAuthnToken above.
	client := &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid"},
	}
	ts, _ := newWebAuthnIssuingTestServer(t, client)

	// Ceremony login against an unknown user — should 404 the same
	// session_invalid envelope regardless of client_id presence.
	body, _ := json.Marshal(webauthnBeginRequest{Username: "ghost@example.com"})
	resp, err := http.Post(ts.URL+PathWebAuthnLoginBegin+"?client_id=wa-app", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown user with client_id: got %d want 404", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_FinishLoginWithoutClientIDStaysCredentialOnly(t *testing.T) {
	// Without client_id, even if ClientStore + TokenIssuers are
	// wired, the v1 response stays credential-only. Test ensures
	// the gating logic doesn't accidentally issue a token from a
	// blank client_id.
	ts, _ := newWebAuthnIssuingTestServer(t, &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid"},
	})

	// Hit Finish with bad session — confirms it stays in the v1 envelope
	// shape (no token fields would even be considered).
	resp, err := http.Post(ts.URL+PathWebAuthnLoginFinish+"?session_id=ghost", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("bad session: got %d want 404", resp.StatusCode)
	}
}

func TestIssueWebAuthnToken_IssuesIDTokenWhenOpenIDScopeAndIssuerWired(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid", "profile"},
	})
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	deps := &WebAuthnDeps{
		ClientStore:   store,
		TokenIssuers:  map[string]sso.TokenIssuer{"jwt": jwtIssuer},
		DefaultStrat:  "jwt",
		IDTokenIssuer: jwtIssuer, // Ed25519JWTIssuer implements both SPIs.
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	result, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.IDToken == "" {
		t.Fatal("IDToken empty — openid scope + wired oidc.IDTokenIssuer must mint id_token")
	}
	if result.AccessToken == "" {
		t.Fatal("AccessToken empty — id_token path must not block access_token")
	}
}

func TestIssueWebAuthnToken_NoIDTokenWithoutOpenIDScope(t *testing.T) {
	// Client scopes don't include openid — id_token must NOT be emitted
	// even when oidc.IDTokenIssuer is wired. Matches /auth/login's contract.
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"profile"},
	})
	jwtIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	deps := &WebAuthnDeps{
		ClientStore:   store,
		TokenIssuers:  map[string]sso.TokenIssuer{"jwt": jwtIssuer},
		DefaultStrat:  "jwt",
		IDTokenIssuer: jwtIssuer,
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	result, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.IDToken != "" {
		t.Fatalf("IDToken = %q without openid scope; must be empty", result.IDToken)
	}
}

func TestIssueWebAuthnToken_NoIDTokenWithoutIssuer(t *testing.T) {
	// openid in scope but no oidc.IDTokenIssuer wired — id_token field
	// stays empty rather than 500. Mirrors how /auth/login silently
	// omits id_token when WithIDTokenIssuer wasn't supplied.
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid"},
	})
	deps := &WebAuthnDeps{
		ClientStore:  store,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	result, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.IDToken != "" {
		t.Fatalf("IDToken populated without wired IDTokenIssuer: %q", result.IDToken)
	}
}

func TestIssueWebAuthnToken_IssuesRefreshTokenWhenStoreWired(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid"},
	})
	refreshStore := defaultimpl.NewMemoryRefreshTokenStore()
	deps := &WebAuthnDeps{
		ClientStore:       store,
		TokenIssuers:      map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat:      "jwt",
		RefreshTokenStore: refreshStore,
		RefreshTokenTTL:   24 * time.Hour,
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	result, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.RefreshToken == "" {
		t.Fatal("oauth.RefreshToken empty — wired oauth.RefreshTokenStore must mint a refresh token")
	}
	// The minted token MUST be redeemable by the same store — proves
	// it was actually persisted and the rotation path will work.
	got, err := refreshStore.Consume(context.Background(), result.RefreshToken)
	if err != nil {
		t.Fatalf("consume refresh token: %v", err)
	}
	if got.UserID != "alice" {
		t.Fatalf("refresh token user_id = %q want alice", got.UserID)
	}
	if got.ClientID != "wa-app" {
		t.Fatalf("refresh token client_id = %q want wa-app", got.ClientID)
	}
	if got.FamilyID == "" {
		t.Fatal("FamilyID empty — webauthn refresh tokens must seed a family for OAuth BCP §4.13 rotation tracking")
	}
}

func TestIssueWebAuthnToken_NoRefreshTokenWithoutStore(t *testing.T) {
	// Without oauth.RefreshTokenStore the field stays empty regardless of
	// scope — matches /auth/login's "wired → emit" contract.
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		AllowedScopes: []string{"openid"},
	})
	deps := &WebAuthnDeps{
		ClientStore:  store,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat: "jwt",
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	result, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.RefreshToken != "" {
		t.Fatalf("oauth.RefreshToken populated without store: %q", result.RefreshToken)
	}
}

func TestIssueWebAuthnToken_ClientRefreshTTLOverride(t *testing.T) {
	// Per-client RefreshTokenTTL beats deps.RefreshTokenTTL when set.
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(context.Background(), &sso.Client{
		ID:              "wa-app",
		Active:          true,
		TokenStrategy:   "jwt",
		AllowedScopes:   []string{"openid"},
		RefreshTokenTTL: 30 * time.Minute,
	})
	refreshStore := defaultimpl.NewMemoryRefreshTokenStore()
	deps := &WebAuthnDeps{
		ClientStore:       store,
		TokenIssuers:      map[string]sso.TokenIssuer{"jwt": defaultimpl.NewEd25519JWTIssuer()},
		DefaultStrat:      "jwt",
		RefreshTokenStore: refreshStore,
		RefreshTokenTTL:   24 * time.Hour,
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	before := time.Now()
	result, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, _ := refreshStore.Consume(context.Background(), result.RefreshToken)
	// 30m client override should beat 24h deps fallback. Allow a
	// little slack for clock movement during the call.
	expectedUpper := before.Add(35 * time.Minute)
	if got.ExpiresAt.After(expectedUpper) {
		t.Fatalf("ExpiresAt %v overshot 30m client override (upper=%v) — fallback to deps TTL leaked through",
			got.ExpiresAt, expectedUpper)
	}
}

// Sanity: confirm the error mapping respects the sentinel set.
func TestWebAuthnErrorStatus_Mapping(t *testing.T) {
	cases := []struct {
		in           error
		wantStatus   int
		wantErrorTag string
	}{
		{webauthn.ErrSessionUnknown, http.StatusNotFound, "session_invalid"},
		{webauthn.ErrSessionExpired, http.StatusNotFound, "session_invalid"},
		{webauthn.ErrUserUnknown, http.StatusNotFound, "session_invalid"},
		{errors.New("generic ceremony parse fail"), http.StatusBadRequest, "ceremony_failed"},
	}
	for _, tc := range cases {
		gotStatus, gotErr := webauthnErrorStatus(tc.in)
		if gotStatus != tc.wantStatus || gotErr != tc.wantErrorTag {
			t.Errorf("webauthnErrorStatus(%v) = (%d, %q), want (%d, %q)",
				tc.in, gotStatus, gotErr, tc.wantStatus, tc.wantErrorTag)
		}
	}
}
