package ssotest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	fcUserID     = "u-frontend"
	fcClientID   = "frontend-app"
	fcSecret     = "frontend-secret"
	fcPassword   = "pw-frontend"
	fcRedirect   = "https://app.example/cb"
	fcIssuer     = "https://sso.example"
	fcVerifier   = "abcdefghijklmnopqrstuvwxyz0123456789-_ABCDEFGHIJK"
	fcSelfServe  = "/me"
	fcAdminEP    = "/api/v1/admin/endpoints"
	fcDiscovery  = "/.well-known/openid-configuration"
	fcOAuthMeta  = "/.well-known/oauth-authorization-server"
	fcPathLogin  = "/auth/login"
	fcPathToken  = "/token"
	fcPathLogout = "/logout"
)

// newFrontendContractHarness builds the stock server the way a separately
// deployed frontend consumes it: public discovery, PKCE code flow, self-
// service and the admin gate, with a SessionManager so the login response
// carries the canonical session_id (frontend-contract.md §3/§8).
func newFrontendContractHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(context.Background(), &sso.User{
		ID: fcUserID, Username: fcUserID, DisplayName: "Frontend User",
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	passwords := defaultimpl.NewMemoryPasswordCredentialStore()
	if err := passwords.SetPassword(context.Background(), fcUserID, fcPassword); err != nil {
		t.Fatalf("seed password: %v", err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: fcClientID, Secret: fcSecret, Active: true, Name: fcClientID,
		TokenStrategy:      "jwt",
		RedirectURIs:       []string{fcRedirect},
		AllowedScopes:      []string{"openid", "profile"},
		RequirePKCE:        true,
		AllowedPKCEMethods: []string{sso.PKCEMethodS256},
		SkipConsent:        true,
	})
	auth := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(ctx context.Context, username, password string) (*sso.AuthResult, error) {
			if username != fcUserID {
				return nil, errFCUnknownUser
			}
			if err := passwords.VerifyPassword(ctx, fcUserID, password); err != nil {
				return nil, errFCUnknownUser
			}
			return &sso.AuthResult{
				UserID: fcUserID, Provider: "password", AuthMethods: []string{"pwd"},
				// Canonical OP-session marker: the code flow mints the session and
				// returns session_id (frontend-contract.md §3).
				CreateSession: true,
			}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519TokenTTL(time.Hour),
		defaultimpl.WithEd25519Issuer(fcIssuer),
	)
	srv := sso.NewServer(
		sso.WithIssuer(fcIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithFeatureGates(sso.FeatureGates{SelfService: sso.Bool(true), AdminAPI: sso.Bool(true)}),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

var errFCUnknownUser = errors.New("unknown user")

func fcPost(t *testing.T, base, path string, body map[string]any) (int, map[string]any, http.Header) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(base+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func fcGet(t *testing.T, base, path, bearer string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func fcChallenge() string {
	sum := sha256.Sum256([]byte(fcVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func fcDecodeJWT(t *testing.T, raw any) map[string]any {
	t.Helper()
	token, ok := raw.(string)
	if !ok {
		t.Fatalf("token = %T, want string", raw)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	claims := map[string]any{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode token claims: %v", err)
	}
	return claims
}

// TestFrontendContract_EndToEndWalk is the cross-project compatibility test
// for docs/frontend-contract.md: it walks the documented surface exactly as
// a separately deployed UI would — discovery, PKCE login, token exchange,
// self-service, admin gate, error vocabulary, logout.
func TestFrontendContract_EndToEndWalk(t *testing.T) {
	srv := newFrontendContractHarness(t)
	base := srv.URL

	// §2 Discovery.
	status, doc := fcGet(t, base, fcDiscovery, "")
	if status != http.StatusOK {
		t.Fatalf("discovery = %d, want 200", status)
	}
	if doc["issuer"] != fcIssuer {
		t.Fatalf("discovery issuer = %v, want %q", doc["issuer"], fcIssuer)
	}
	for _, key := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
		if _, ok := doc[key].(string); !ok {
			t.Errorf("discovery missing %s: %v", key, doc)
		}
	}
	if status, _ := fcGet(t, base, fcOAuthMeta, ""); status != http.StatusOK {
		t.Errorf("oauth-authorization-server metadata = %d, want 200", status)
	}

	// §3 Login (PKCE S256, code flow, canonical session_id).
	status, body, _ := fcPost(t, base, fcPathLogin, map[string]any{
		"provider":              "password",
		"client_id":             fcClientID,
		"redirect_uri":          fcRedirect,
		"response_type":         "code",
		"scope":                 []string{"openid", "profile"},
		"code_challenge":        fcChallenge(),
		"code_challenge_method": "S256",
		"credential":            map[string]string{"username": fcUserID, "password": fcPassword},
	})
	if status != http.StatusOK {
		t.Fatalf("login = %d %v, want 200", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("login returned no code: %v", body)
	}
	sessionID, _ := body["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("login returned no session_id: %v", body)
	}

	// §3 Token exchange: access + id token, sid == session_id, aud == client.
	status, tokens, _ := fcPost(t, base, fcPathToken, map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  fcRedirect,
		"client_id":     fcClientID,
		"client_secret": fcSecret,
		"code_verifier": fcVerifier,
	})
	if status != http.StatusOK {
		t.Fatalf("token = %d %v, want 200", status, tokens)
	}
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("no access_token: %v", tokens)
	}
	rawIDToken, _ := tokens["id_token"].(string)
	if rawIDToken == "" {
		t.Fatalf("no id_token: %v", tokens)
	}
	idClaims := fcDecodeJWT(t, rawIDToken)
	if idClaims["iss"] != fcIssuer || idClaims["aud"] != fcClientID {
		t.Errorf("id_token iss/aud = %v/%v, want %q/%q", idClaims["iss"], idClaims["aud"], fcIssuer, fcClientID)
	}
	if idClaims["sid"] != sessionID {
		t.Errorf("id_token sid = %v, want session %q", idClaims["sid"], sessionID)
	}

	// §5 Self-service account overview with the access token.
	status, me := fcGet(t, base, fcSelfServe, accessToken)
	if status != http.StatusOK {
		t.Fatalf("/me = %d %v, want 200", status, me)
	}
	if me["sub"] != fcUserID {
		t.Errorf("/me sub = %v, want %q", me["sub"], fcUserID)
	}

	// §6 Admin gate: the runtime endpoint inventory is the documented
	// runtime truth frontends pin against (frontend-contract.md §6 — the
	// 401 admin bearer challenge itself is enforced by the full server's
	// AdminMiddleware composition; see cmd/sso-server admin tests).
	status, adminBody := fcGet(t, base, fcAdminEP, "")
	if status != http.StatusOK {
		t.Fatalf("/api/v1/admin/endpoints = %d %v, want 200", status, adminBody)
	}
	endpoints, ok := adminBody["endpoints"].([]any)
	if !ok {
		t.Fatalf("endpoints inventory shape = %T, want array", adminBody["endpoints"])
	}
	var foundLogin, foundMe bool
	for _, item := range endpoints {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		path, _ := entry["path"].(string)
		foundLogin = foundLogin || path == fcPathLogin
		foundMe = foundMe || path == fcSelfServe
	}
	if !foundLogin || !foundMe {
		t.Errorf("endpoint inventory missing /auth/login or /me: %v", endpoints)
	}

	// §3 Error vocabulary: unknown provider is a byte-shaped 400
	// unsupported_provider carrying iss (RFC 9207).
	status, errBody, _ := fcPost(t, base, fcPathLogin, map[string]any{
		"provider":   "no-such-provider",
		"client_id":  fcClientID,
		"credential": map[string]string{"username": fcUserID, "password": fcPassword},
	})
	if status != http.StatusBadRequest || errBody["error"] != "unsupported_provider" {
		t.Fatalf("unknown provider = %d %v, want 400 unsupported_provider", status, errBody)
	}
	if errBody["iss"] != fcIssuer {
		t.Errorf("error body iss = %v, want %q (RFC 9207)", errBody["iss"], fcIssuer)
	}

	// §8 Logout: the canonical session dies — a prompt=none silent renewal
	// with the pre-logout id_token_hint must now fail with login_required
	// (no live session behind the hint). The stateless access token itself
	// stays valid until exp unless presented at logout (standard OAuth).
	status, out, _ := fcPost(t, base, fcPathLogout, map[string]any{"session_id": sessionID})
	if status != http.StatusOK || out["status"] != "logged_out" {
		t.Fatalf("logout = %d %v, want 200 logged_out", status, out)
	}
	status, dead, _ := fcPost(t, base, fcPathLogin, map[string]any{
		"client_id":     fcClientID,
		"redirect_uri":  fcRedirect,
		"response_type": "code",
		"scope":         []string{"openid"},
		"prompt":        "none",
		"id_token_hint": rawIDToken,
	})
	if status != http.StatusBadRequest || dead["error"] != "login_required" {
		t.Fatalf("prompt=none after logout = %d %v, want 400 login_required", status, dead)
	}
}

// TestFrontendContract_PromptNoneSilentRenewal covers the documented
// prompt=none renewal: a live session plus id_token_hint renews tokens
// without UI (frontend-contract.md §3).
func TestFrontendContract_PromptNoneSilentRenewal(t *testing.T) {
	srv := newFrontendContractHarness(t)
	base := srv.URL

	_, body, _ := fcPost(t, base, fcPathLogin, map[string]any{
		"provider":              "password",
		"client_id":             fcClientID,
		"redirect_uri":          fcRedirect,
		"response_type":         "code",
		"scope":                 []string{"openid"},
		"code_challenge":        fcChallenge(),
		"code_challenge_method": "S256",
		"credential":            map[string]string{"username": fcUserID, "password": fcPassword},
	})
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("login returned no code: %v", body)
	}
	_, tokens, _ := fcPost(t, base, fcPathToken, map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  fcRedirect,
		"client_id":     fcClientID,
		"client_secret": fcSecret,
		"code_verifier": fcVerifier,
	})
	idToken, _ := tokens["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token: %v", tokens)
	}

	// prompt=none with the id_token_hint renews silently.
	status, renew, _ := fcPost(t, base, fcPathLogin, map[string]any{
		"client_id":     fcClientID,
		"redirect_uri":  fcRedirect,
		"response_type": "code",
		"scope":         []string{"openid"},
		"prompt":        "none",
		"id_token_hint": idToken,
	})
	if status != http.StatusOK || renew["access_token"] == nil {
		t.Fatalf("prompt=none = %d %v, want renewed tokens", status, renew)
	}
	// The renewed id_token reuses the ORIGINAL auth_time (no fresh auth event).
	orig := fcDecodeJWT(t, idToken)
	renewed := fcDecodeJWT(t, renew["id_token"])
	if renewed["auth_time"] != orig["auth_time"] {
		t.Errorf("renewed auth_time = %v, want original %v", renewed["auth_time"], orig["auth_time"])
	}
	if renewed["sid"] != orig["sid"] {
		t.Errorf("renewed sid = %v, want original %v (same session)", renewed["sid"], orig["sid"])
	}
}
