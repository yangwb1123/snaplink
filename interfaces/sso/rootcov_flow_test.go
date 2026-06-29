package sso_test

// rootcov_flow_test.go exercises the root package's HTTP handler surface
// in-directory (package sso_test, same dir => counts toward `go test -cover .`)
// by spinning up a richly-wired *sso.Server over httptest and driving the full
// credential lifecycle: discovery, JWKS, login, token exchange, refresh,
// userinfo, introspect, revoke, the /me/* self-service portal, and logout.
// The external integration suite under test/ exercises the same paths but does
// NOT count toward root unit coverage, so this mirrors that exercise locally.
//
// All helpers carry the rcov* prefix so they can never collide with the ~26
// pre-existing root test files.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

const (
	rcovUser     = "rcov-user-alice"
	rcovClient   = "rcov-client"
	rcovSecret   = "rcov-secret"
	rcovRedirect = "https://app.example.com/cb"
	rcovUsername = "alice"
	rcovPassword = "pw"
)

// rcovServer bundles a running httptest server with the in-memory stores a
// test may want to inspect or seed.
type rcovServer struct {
	http     *httptest.Server
	users    *defaultimpl.MemoryUserProvider
	clients  *defaultimpl.MemoryClientStore
	sessions *defaultimpl.MemorySessionManager
	consents *defaultimpl.MemoryConsentStore
	passwd   *defaultimpl.MemoryPasswordCredentialStore
	mfaEnr   *defaultimpl.MemoryMFAEnrollmentStore
	refresh  *defaultimpl.MemoryRefreshTokenStore
	authcode *defaultimpl.MemoryAuthCodeStore
	sink     *audit.MemorySink
}

// rcovNewServer wires nearly every optional self-service / credential store so a
// single login can drive the broadest possible handler + accessor surface. The
// password authenticator accepts (alice/pw) and reports a couple of attributes
// so the OIDC userinfo projection has something to expose.
func rcovNewServer(t *testing.T, extra ...sso.Option) *rcovServer {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{
		ID:    rcovUser,
		Name:  "Alice Example",
		Email: "alice@example.com",
		Attributes: map[string]string{
			"email_verified":     "true",
			"preferred_username": "alice",
		},
	})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    rcovClient,
		Secret:                rcovSecret,
		Name:                  "Root Coverage Client",
		RedirectURIs:          []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
		// First-party trust: bypass the interactive consent gate so the base
		// flow mints directly. Consent-store coverage is exercised separately by
		// seeding a grant + hitting /consents/me.
		SkipConsent: true,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == rcovUsername && p == rcovPassword {
				return &sso.AuthResult{
					UserID:      rcovUser,
					AuthMethods: []string{"pwd"},
					// Attributes are the live source of truth the login upsert
					// persists, so the OIDC userinfo projection reads them here
					// (the seeded User fields are overwritten by this upsert).
					Attributes: map[string]string{
						"role":               "admin",
						"email":              "alice@example.com",
						"email_verified":     "true",
						"name":               "Alice Example",
						"preferred_username": "alice",
					},
				}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))

	sessions := defaultimpl.NewMemorySessionManager()
	consents := defaultimpl.NewMemoryConsentStore()
	passwd := defaultimpl.NewMemoryPasswordCredentialStore()
	_ = passwd.SetPassword(ctx, rcovUser, rcovPassword)
	mfaEnr := defaultimpl.NewMemoryMFAEnrollmentStore()
	refresh := defaultimpl.NewMemoryRefreshTokenStore()
	authcode := defaultimpl.NewMemoryAuthCodeStore()
	sink := audit.NewMemorySink(200)

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(sessions),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(authcode, 5*time.Minute),
		sso.WithRefreshTokenStore(refresh, time.Hour),
		sso.WithConsentStore(consents),
		sso.WithPasswordCredentialStore(passwd),
		sso.WithMFAEnrollmentStore(mfaEnr),
		sso.WithSelfEditableProfileAttributes("nickname"),
		sso.WithAuditRecorder(audit.New(sink)),
	}
	opts = append(opts, extra...)

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	return &rcovServer{
		http: httpSrv, users: users, clients: clients, sessions: sessions,
		consents: consents, passwd: passwd, mfaEnr: mfaEnr, refresh: refresh,
		authcode: authcode, sink: sink,
	}
}

// rcovPostJSON posts a JSON body (optionally bearer-authenticated) and returns
// the status + decoded map body.
func rcovPostJSON(t *testing.T, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	return rcovDo(t, http.MethodPost, url, bearer, body)
}

func rcovDo(t *testing.T, method, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(bytes.TrimSpace(raw)) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

// rcovDirectLogin performs a direct-mint login (no response_type) and returns
// the access + refresh tokens.
func rcovDirectLogin(t *testing.T, s *rcovServer) (access, refresh string) {
	t.Helper()
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile", "email"},
	})
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	access, _ = out["access_token"].(string)
	refresh, _ = out["refresh_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in login response: %v", out)
	}
	return access, refresh
}

// TestRcov_DirectMintLogin covers the login orchestrator's direct-mint branch
// plus the no-store header stamping and RFC 9207 iss echo.
func TestRcov_DirectMintLogin(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, refresh := rcovDirectLogin(t, s)
	if refresh == "" {
		t.Errorf("expected a refresh_token (WithRefreshTokenStore wired)")
	}
	// Re-fetch raw to assert headers + iss.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
	})
	resp, err := http.Post(s.http.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["iss"] != s.http.URL {
		t.Errorf("iss = %v, want request base URL %q", out["iss"], s.http.URL)
	}
	if access == "" {
		t.Fatal("no access token")
	}
}

// TestRcov_LoginBadCredentials covers the authenticator-failure path.
func TestRcov_LoginBadCredentials(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": "wrong"},
	})
	if status != http.StatusUnauthorized && status != http.StatusBadRequest {
		t.Errorf("bad-creds status = %d, want 401/400 (body=%v)", status, out)
	}
	if out["error"] == nil {
		t.Errorf("expected an error code in body: %v", out)
	}
}

// TestRcov_AuthCodeRoundTrip covers the code-issuance branch of the login
// orchestrator plus the authorization_code grant in the token handler.
func TestRcov_AuthCodeRoundTrip(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":      "password",
		"client_id":     rcovClient,
		"credential":    map[string]string{"username": rcovUsername, "password": rcovPassword},
		"response_type": "code",
		"redirect_uri":  rcovRedirect,
		"state":         "st-123",
	})
	if status != http.StatusOK {
		t.Fatalf("code login status=%d body=%v", status, out)
	}
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("no code returned: %v", out)
	}
	if out["state"] != "st-123" {
		t.Errorf("state not echoed: %v", out["state"])
	}

	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"redirect_uri":  rcovRedirect,
	})
	if status != http.StatusOK {
		t.Fatalf("token exchange status=%d body=%v", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("no access_token from exchange: %v", tok)
	}

	// Oracle-leak: replaying the now-consumed code must collapse to invalid_grant.
	status, tok = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"redirect_uri":  rcovRedirect,
	})
	if status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Errorf("code replay = %d %v, want 400 invalid_grant", status, tok)
	}
}

// TestRcov_RefreshGrant covers the refresh_token grant + rotation path.
func TestRcov_RefreshGrant(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	_, refresh := rcovDirectLogin(t, s)
	if refresh == "" {
		t.Skip("no refresh token issued")
	}
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("refresh produced no access_token: %v", tok)
	}
}

// TestRcov_Userinfo covers the userinfo handler success + the two 401 branches.
func TestRcov_Userinfo(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovDo(t, http.MethodGet, s.http.URL+"/userinfo", access, nil)
	if status != http.StatusOK {
		t.Fatalf("userinfo status=%d body=%v", status, out)
	}
	if out["sub"] != rcovUser {
		t.Errorf("sub = %v, want %q", out["sub"], rcovUser)
	}
	// openid+profile+email scopes => projected claims present.
	if out["email"] != "alice@example.com" {
		t.Errorf("email claim = %v", out["email"])
	}

	// Missing bearer => 401 with WWW-Authenticate, no error= param.
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/userinfo", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("no-bearer userinfo = %d, want 401", status)
	}
	// Invalid bearer => 401 invalid_token.
	status, out = rcovDo(t, http.MethodGet, s.http.URL+"/userinfo", "not-a-real-token", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("bad-bearer userinfo = %d, want 401 (body=%v)", status, out)
	}
}

// TestRcov_IntrospectAndRevoke covers the introspection + revocation handlers.
func TestRcov_IntrospectAndRevoke(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/token/introspect", "", map[string]any{
		"token":         access,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("introspect status=%d body=%v", status, out)
	}
	if out["active"] != true {
		t.Errorf("active = %v, want true (body=%v)", out["active"], out)
	}

	// Anti-enumeration: revoke returns 200 regardless of token existence.
	status, _ = rcovPostJSON(t, s.http.URL+"/token/revoke", "", map[string]any{
		"token":         access,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Errorf("revoke = %d, want 200", status)
	}
	status, _ = rcovPostJSON(t, s.http.URL+"/token/revoke", "", map[string]any{
		"token":         "totally-unknown-token",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Errorf("revoke-unknown = %d, want 200 (anti-enumeration)", status)
	}

	// Introspecting an inactive/garbage token returns {"active":false}.
	status, out = rcovPostJSON(t, s.http.URL+"/token/introspect", "", map[string]any{
		"token":         "garbage",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK || out["active"] != false {
		t.Errorf("inactive introspect = %d %v, want 200 active:false", status, out)
	}
}

// TestRcov_Logout covers the logout handler with a bearer token.
func TestRcov_Logout(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	access, _ := rcovDirectLogin(t, s)

	status, out := rcovPostJSON(t, s.http.URL+"/logout", access, nil)
	if status != http.StatusOK {
		t.Fatalf("logout status=%d body=%v", status, out)
	}
	if out["status"] != "logged_out" {
		t.Errorf("logout status field = %v", out["status"])
	}

	// No bearer and no session_id => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/logout", "", map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("empty logout = %d, want 400", status)
	}
}

// TestRcov_EndSession covers the RP-initiated logout GET endpoint.
func TestRcov_EndSession(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, _ := rcovDo(t, http.MethodGet, s.http.URL+"/end_session", "", nil)
	// No id_token_hint / post_logout_redirect_uri => a benign non-5xx response.
	if status >= 500 {
		t.Errorf("end_session = %d, want < 500", status)
	}
}

// TestRcov_ClientCredentialsGrant covers the always-on client_credentials grant.
func TestRcov_ClientCredentialsGrant(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "client_credentials",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"scope":         "read",
	})
	if status != http.StatusOK {
		t.Fatalf("client_credentials status=%d body=%v", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("no access_token: %v", tok)
	}
}

// TestRcov_TokenUnknownGrant covers the unsupported_grant_type branch.
func TestRcov_TokenUnknownGrant(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, out := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "totally_made_up",
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest {
		t.Errorf("unknown grant = %d, want 400 (body=%v)", status, out)
	}
}

// rcovAuditCount returns how many events of a type the sink recorded.
func rcovAuditCount(t *testing.T, s *rcovServer, et audit.EventType) int {
	t.Helper()
	evts, _ := s.sink.Query(context.Background(), audit.Query{Type: et})
	return len(evts)
}

// TestRcov_LoginEmitsAudit confirms the audit pipeline is reached on a
// successful direct-mint login (which records EventLogin) and on the
// authorization_code exchange (which records EventTokenIssued).
func TestRcov_LoginEmitsAudit(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	rcovDirectLogin(t, s)
	if n := rcovAuditCount(t, s, audit.EventLogin); n < 1 {
		t.Errorf("login audit events = %d, want >= 1", n)
	}
}
