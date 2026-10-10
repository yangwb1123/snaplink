package ssotest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc/browsersso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type browserStepUpScorer struct{}

func (browserStepUpScorer) Score(_ context.Context, req *spi.RiskRequest) (*spi.RiskAssessment, error) {
	decision := spi.DecisionAllow
	if req.ClientID == "rp-b" {
		decision = spi.DecisionRequireMFA
	}
	return &spi.RiskAssessment{Decision: decision}, nil
}

func TestE2E_BrowserSSO_RiskMFAIsNotBypassed(t *testing.T) {
	secret := []byte("12345678901234567890")
	provider := authenticators.NewTOTPMFAProvider(authenticators.NewTOTPAuthenticator(&totpStubStore{secret: secret}))
	h := newBrowserHarness(t, true, false, sso.WithRiskScorer(browserStepUpScorer{}), sso.WithMFAProvider(provider), sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), time.Minute))
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	_, pending, headers := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if pending["error"] != "mfa_required" || pending["mfa_challenge_id"] == nil || pending["code"] != nil || headers.Get("Set-Cookie") != "" {
		t.Fatal("risk step-up was skipped")
	}
	status, finished, _ := browserPost(t, h, "/auth/mfa", map[string]any{"mfa_challenge_id": pending["mfa_challenge_id"], "mfa_method": "totp", "code": validTOTPCode(t, secret)})
	if status != 200 || finished["code"] == nil || h.passwordCalls.Load() != 1 {
		t.Fatalf("MFA resume failed: %d error=%v", status, finished["error"])
	}
}

func TestE2E_BrowserSSO_PromptNoneNeverExposesInteractiveChallenge(t *testing.T) {
	for _, mfa := range []bool{false, true} {
		t.Run(map[bool]string{false: "consent", true: "mfa"}[mfa], func(t *testing.T) {
			var opts []sso.Option
			if mfa {
				provider := authenticators.NewTOTPMFAProvider(authenticators.NewTOTPAuthenticator(&totpStubStore{secret: []byte("12345678901234567890")}))
				opts = []sso.Option{sso.WithRiskScorer(browserStepUpScorer{}), sso.WithMFAProvider(provider), sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), time.Minute)}
			}
			h := newBrowserHarness(t, true, !mfa, opts...)
			browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
			request := browserRequest("rp-b", true)
			request["prompt"] = "none"
			_, out, _ := browserPost(t, h, "/auth/login", request)
			want := "consent_required"
			if mfa {
				want = "interaction_required"
			}
			if out["error"] != want || out["mfa_challenge_id"] != nil || out["consent_challenge_id"] != nil || out["login_transaction_id"] != nil || out["code"] != nil {
				t.Fatalf("interactive prompt=none response: error=%v", out["error"])
			}
		})
	}
}

func TestE2E_BrowserSSO_CookiePurposeAndExpiry(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	original := browserCookie(t, h)
	claims, err := h.issuer.ValidateBrowserSession(context.Background(), original.Value)
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := url.Parse(h.http.URL)
	for _, tc := range []struct {
		name, purpose, audience string
		authTime, expires       time.Time
		maxAge                  any
	}{
		{"expired", "browser-op-session", "urn:snaplink:browser-op-session", time.Now().Add(-time.Hour), time.Now().Add(-time.Minute), nil},
		{"old authentication", "browser-op-session", "urn:snaplink:browser-op-session", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 10},
		{"wrong purpose", "another-use", "urn:snaplink:browser-op-session", time.Now(), time.Now().Add(time.Hour), nil},
		{"wrong audience", "browser-op-session", "rp-b", time.Now(), time.Now().Add(time.Hour), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cookie, err := h.issuer.SignJWT(context.Background(), core.JWTTypBrowserSession, map[string]any{"iss": browserIssuer, "aud": tc.audience, "sub": claims.Subject, "sid": claims.SID, "auth_time": tc.authTime.Unix(), "exp": tc.expires.Unix(), "amr": []string{"pwd"}, "ext": map[string]string{"provider": "password", "purpose": tc.purpose}})
			if err != nil {
				t.Fatal(err)
			}
			h.browser.Jar.SetCookies(origin, []*http.Cookie{{Name: browsersso.CookieName, Value: cookie, Path: "/"}})
			request := browserRequest("rp-b", true)
			if tc.maxAge != nil {
				request["max_age"] = tc.maxAge
			}
			_, out, _ := browserPost(t, h, "/auth/login", request)
			if out["error"] != "login_required" || out["code"] != nil {
				t.Fatal("invalid cookie authenticated")
			}
		})
	}
	// A correctly signed RP ID token is not an OP cookie.
	idToken, err := h.issuer.SignJWT(context.Background(), "JWT", map[string]any{"iss": browserIssuer, "aud": "rp-a", "sub": "alice", "sid": claims.SID, "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	h.browser.Jar.SetCookies(origin, []*http.Cookie{{Name: browsersso.CookieName, Value: idToken, Path: "/"}})
	_, out, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if out["error"] != "login_required" {
		t.Fatal("RP token substituted for OP cookie")
	}
}

func TestE2E_BrowserSSO_DeactivatedUserAndUnavailableStore(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	user, _ := h.users.GetByID(context.Background(), "alice")
	user.Attributes[core.UserAttrActive] = core.UserAttrInactive
	if err := h.users.CreateOrUpdate(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	_, inactive, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
	if inactive["error"] != "account_locked" {
		t.Fatal("deactivated user authenticated")
	}
	live := newBrowserHarness(t, true, false)
	browserPost(t, live, "/auth/login", browserRequest("rp-a", false))
	broken := &unavailableBrowserSessions{SessionManager: live.sessions}
	issuer := live.issuer
	server := sso.NewServer(sso.WithIssuer(browserIssuer), sso.WithSessionManager(broken), sso.WithBrowserSSO(issuer, issuer))
	cookie := browserCookie(t, live)
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"client_id":"rp-b","response_type":"code","resume_session":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 503 || !strings.Contains(recorder.Body.String(), "temporarily_unavailable") {
		t.Fatal("store outage masqueraded as absent identity")
	}
}

func TestE2E_BrowserSSO_ClientProviderBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		change     func(*core.Client)
	}{
		{"inactive client", "inactive_client", func(c *core.Client) { c.Active = false }},
		{"provider policy", core.ErrAuthenticatorNotAllowed, func(c *core.Client) { c.AllowedAuthenticators = []string{"webauthn"} }},
		{"passwordless policy", "passwordless_required", func(c *core.Client) { c.AllowPasswordlessOnly = true }},
		{"required PAR", "invalid_request", func(c *core.Client) { c.RequirePAR = true }},
		{"required JAR", "invalid_request", func(c *core.Client) { c.RequireSignedRequestObject = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clients := defaultimpl.NewMemoryClientStore()
			for _, id := range []string{"rp-a", "rp-b"} {
				client := &core.Client{ID: id, Active: true, SkipConsent: true, TokenStrategy: "jwt", RedirectURIs: []string{"https://" + id + ".example/callback"}}
				if id == "rp-b" {
					tc.change(client)
				}
				clients.AddSeed(client)
			}
			h := newBrowserHarness(t, true, false, sso.WithClientStore(clients))
			browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
			_, out, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
			if out["error"] != tc.want || out["code"] != nil || h.passwordCalls.Load() != 1 {
				t.Fatalf("cookie bypassed client gate: error=%v want=%s", out["error"], tc.want)
			}
		})
	}
}

func TestE2E_BrowserSSO_MissingUserIsNotStoreOutage(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	for _, tc := range []struct {
		name, want string
		status     int
		err        error
	}{
		{"deleted user", "login_required", 400, core.ErrNoSuchUser},
		{"user store outage", "temporarily_unavailable", 503, errors.New("identity store unavailable")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clients := defaultimpl.NewMemoryClientStore()
			clients.AddSeed(&core.Client{ID: "rp-b", Active: true})
			other := sso.NewServer(sso.WithIssuer(browserIssuer), sso.WithClientStore(clients), sso.WithSessionManager(h.sessions), sso.WithUserProvider(&failedBrowserUsers{UserProvider: h.users, err: tc.err}), sso.WithBrowserSSO(h.issuer, h.issuer))
			request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"client_id":"rp-b","response_type":"code","resume_session":true}`))
			request.Header.Set("Content-Type", "application/json")
			request.AddCookie(browserCookie(t, h))
			recorder := httptest.NewRecorder()
			other.Handler().ServeHTTP(recorder, request)
			if recorder.Code != tc.status || !strings.Contains(recorder.Body.String(), tc.want) {
				t.Fatalf("wrong missing/outage boundary: status=%d", recorder.Code)
			}
		})
	}
}

type failedBrowserUsers struct {
	core.UserProvider
	err error
}

func (u *failedBrowserUsers) GetByID(context.Context, string) (*core.User, error) { return nil, u.err }

func TestE2E_BrowserSSO_TamperIssuerAndBearerSubstitution(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	cookie := browserCookie(t, h)
	request, _ := http.NewRequest(http.MethodGet, h.http.URL+"/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+cookie.Value)
	response, err := h.browser.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("resource endpoint accepted cookie bearer")
	}
	claims, err := h.issuer.ValidateBrowserSession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := h.issuer.SignJWT(context.Background(), core.JWTTypBrowserSession, map[string]any{"iss": "https://other-op.example", "aud": "urn:snaplink:browser-op-session", "sub": claims.Subject, "sid": claims.SID, "auth_time": claims.AuthTime.Unix(), "exp": claims.ExpiresAt.Unix(), "ext": map[string]string{"provider": "password", "purpose": "browser-op-session"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(cookie.Value, ".")
	first := "A"
	if strings.HasPrefix(parts[2], first) {
		first = "B"
	}
	parts[2] = first + parts[2][1:]
	origin, _ := url.Parse(h.http.URL)
	for name, value := range map[string]string{"tampered": strings.Join(parts, "."), "foreign issuer": foreign} {
		t.Run(name, func(t *testing.T) {
			h.browser.Jar.SetCookies(origin, []*http.Cookie{{Name: browsersso.CookieName, Value: value, Path: "/"}})
			_, out, _ := browserPost(t, h, "/auth/login", browserRequest("rp-b", true))
			if out["error"] != "login_required" || out["code"] != nil {
				t.Fatal("invalid cookie authenticated")
			}
		})
	}
}

type unavailableBrowserSessions struct{ core.SessionManager }

func (*unavailableBrowserSessions) Get(context.Context, string) (*core.Session, error) {
	return nil, errors.New("session store unavailable")
}

type failedBrowserSigner struct {
	browsersso.Signer
	fail bool
}

func (s *failedBrowserSigner) SignJWT(ctx context.Context, typ string, payload any) (string, error) {
	if s.fail {
		return "", errors.New("browser-cookie signing unavailable")
	}
	return s.Signer.SignJWT(ctx, typ, payload)
}

func TestE2E_BrowserSSO_FailedFreshCookieNeverKeepsPreviousAccount(t *testing.T) {
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(browserIssuer))
	signer := &failedBrowserSigner{Signer: issuer}
	password := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(func(_ context.Context, username, password string) (*core.AuthResult, error) {
		if password != "test-password" {
			return nil, errors.New("invalid credential")
		}
		return &core.AuthResult{UserID: username, ExternalID: username, Provider: "password", AuthMethods: []string{"pwd"}, Attributes: map[string]string{"email": username + "@example.test"}}, nil
	}))
	h := newBrowserHarness(t, true, false, sso.WithBrowserSSO(signer, issuer), sso.WithAuthenticator(password))
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	original := browserCookie(t, h)
	signer.fail = true
	request := browserRequest("rp-b", false)
	request["credential"] = map[string]string{"username": "bob", "password": "test-password"}
	status, out, headers := browserPost(t, h, "/auth/login", request)
	if status != 200 || out["code"] == nil || !strings.Contains(headers.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatal("fresh grant/cookie failure boundary changed")
	}
	origin, _ := url.Parse(h.http.URL)
	for _, cookie := range h.browser.Jar.Cookies(origin) {
		if cookie.Name == browsersso.CookieName {
			t.Fatal("previous account stayed selected after fresh-cookie failure")
		}
	}
	claims, err := issuer.ValidateBrowserSession(context.Background(), original.Value)
	if err != nil {
		t.Fatal(err)
	}
	if live, err := h.sessions.Get(context.Background(), claims.SID); err != nil || live.UserID != "alice" || live.Revoked {
		t.Fatal("cookie clearing revoked independent RP authorization")
	}
	_, discovery, _ := browserPost(t, h, "/auth/login", map[string]any{"client_id": "rp-b"})
	if discovery[browsersso.KeyAvailable] != false {
		t.Fatal("cookie failure advertised reusable identity")
	}
}

func TestE2E_BrowserSSO_SessionMissKeepsValidatedErrorDelivery(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	for _, tc := range []struct {
		name, redirect string
		valid          bool
	}{
		{"registered RP", "https://rp-b.example/callback", true},
		{"attacker redirect", "https://attacker.example/callback", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := browserRequest("rp-b", true)
			request["prompt"], request["redirect_uri"] = "none", tc.redirect
			_, out, _ := browserPost(t, h, "/auth/login", request)
			if out["error"] != "login_required" || out["code"] != nil {
				t.Fatal("missing identity authenticated")
			}
			if tc.valid {
				if out["redirect_uri_validated"] != true || out["redirect_uri"] != tc.redirect || out["state"] != "rp-b-state" || out["response_mode"] != "query" {
					t.Fatal("legitimate silent error lost RP delivery proof")
				}
			} else if out["redirect_uri_validated"] != nil || out["redirect_uri"] != nil {
				t.Fatal("session miss attested an attacker redirect")
			}
		})
	}
}

func TestE2E_BrowserSSO_SharedReplicaResolvesCanonicalSession(t *testing.T) {
	h := newBrowserHarness(t, true, false)
	browserPost(t, h, "/auth/login", browserRequest("rp-a", false))
	// Independent handler instance shares only signing keys + canonical store,
	// never a per-process authentication cache or application-token storage.
	other := sso.NewServer(sso.WithIssuer(browserIssuer), sso.WithSessionManager(h.sessions), sso.WithBrowserSSO(h.issuer, h.issuer))
	request := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"client_id":"rp-b"}`))
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(browserCookie(t, h))
	recorder := httptest.NewRecorder()
	other.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), `"op_session_available":true`) {
		t.Fatal("replica could not resolve canonical OP session")
	}
}
