package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
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
	fclClientID  = "fcl-client"
	fclSecret    = "fcl-secret"
	fclUserID    = "u-fcl"
	fclLoginURI  = "https://app.example/post-logout"
	fclLogoutURI = "https://app.example/oidc/frontchannel-logout"
)

// newFrontchannelHarness mirrors newEndSessionHarness but registers
// FrontchannelLogoutURI on the client so /end_session emits the FCL
// HTML response instead of the bare 302/204.
func newFrontchannelHarness(t *testing.T, registerFCL bool) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: fclUserID})
	clients := defaultimpl.NewMemoryClientStore()
	c := &sso.Client{
		ID: fclClientID, Secret: fclSecret, Active: true,
		AllowedAuthenticators:  []string{"password"},
		TokenStrategy:          "jwt",
		AllowedScopes:          []string{"openid"},
		PostLogoutRedirectURIs: []string{fclLoginURI},
	}
	if registerFCL {
		c.FrontchannelLogoutURI = fclLogoutURI
	}
	clients.AddSeed(c)
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: fclUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithIDTokenIssuer(issuer),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func fclLogin(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  fclClientID,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"openid"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	id, _ := out["id_token"].(string)
	if id == "" {
		t.Fatalf("no id_token: %s", raw)
	}
	return id
}

func TestFCL_RendersIframeWhenClientOptsIn(t *testing.T) {
	srv := newFrontchannelHarness(t, true)
	idToken := fclLogin(t, srv)

	resp, err := nonFollowingClient().Get(srv.URL + "/end_session?id_token_hint=" + idToken)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("content-type: got %q, want text/html prefix", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	// The iframe src starts with the configured URI and now also
	// carries `sid` + `iss` query params per OIDC FCL §3.
	if !strings.Contains(string(body), `src="`+fclLogoutURI+`?sid=`) {
		t.Fatalf("iframe src missing or lacks sid: %s", body)
	}
	if !strings.Contains(string(body), `&amp;iss=`) {
		t.Fatalf("iframe src missing iss param: %s", body)
	}
}

func TestFCL_MetaRefreshWhenRedirectAllowlisted(t *testing.T) {
	srv := newFrontchannelHarness(t, true)
	idToken := fclLogin(t, srv)

	u := srv.URL + "/end_session?id_token_hint=" + idToken +
		"&post_logout_redirect_uri=" + fclLoginURI +
		"&state=keep-this"
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, `http-equiv="refresh"`) {
		t.Fatalf("meta refresh missing: %s", s)
	}
	if !strings.Contains(s, "state=keep-this") {
		t.Fatalf("state lost in redirect: %s", s)
	}
	if !strings.Contains(s, `src="`+fclLogoutURI+`?sid=`) {
		t.Fatalf("iframe missing or lacks sid: %s", s)
	}
	// state echo lives on the meta-refresh URL, NOT on the
	// iframe src (RP-Initiated Logout vs FCL — different
	// targets); sid + iss are on the iframe.
	if !strings.Contains(s, `&amp;iss=`) {
		t.Fatalf("iframe iss missing: %s", s)
	}
}

func TestFCL_NoRedirectWhenURIRejected(t *testing.T) {
	srv := newFrontchannelHarness(t, true)
	idToken := fclLogin(t, srv)

	u := srv.URL + "/end_session?id_token_hint=" + idToken +
		"&post_logout_redirect_uri=https://attacker.example/"
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if strings.Contains(s, "attacker.example") {
		t.Fatalf("attacker URI leaked into FCL page: %s", s)
	}
	if strings.Contains(s, `http-equiv="refresh"`) {
		t.Fatalf("meta refresh emitted for un-allowlisted redirect: %s", s)
	}
	if !strings.Contains(s, `src="`+fclLogoutURI+`?sid=`) {
		t.Fatalf("iframe still expected even without redirect: %s", s)
	}
}

func TestFCL_HeadersHardened(t *testing.T) {
	srv := newFrontchannelHarness(t, true)
	idToken := fclLogin(t, srv)

	resp, err := nonFollowingClient().Get(srv.URL + "/end_session?id_token_hint=" + idToken)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// XFO DENY blocks an attacker from embedding our /end_session
	// response in their own iframe to clickjack a logout. Real RP
	// iframes inside our page are unaffected — XFO controls who
	// can embed US, not who WE embed.
	if v := resp.Header.Get("X-Frame-Options"); v != "DENY" {
		t.Fatalf("X-Frame-Options: got %q, want DENY", v)
	}
	if v := resp.Header.Get("Cache-Control"); v != "no-store" {
		t.Fatalf("Cache-Control: got %q, want no-store", v)
	}
	if v := resp.Header.Get("Referrer-Policy"); v != "no-referrer" {
		t.Fatalf("Referrer-Policy: got %q, want no-referrer", v)
	}
}

func TestFCL_FallsBackTo302WhenNotOptedIn(t *testing.T) {
	srv := newFrontchannelHarness(t, false)
	idToken := fclLogin(t, srv)

	u := srv.URL + "/end_session?id_token_hint=" + idToken +
		"&post_logout_redirect_uri=" + fclLoginURI
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status: got %d, want 302 (FCL must not engage when client unset)", resp.StatusCode)
	}
}

func TestFCL_FallsBackTo204WhenNotOptedInAndNoRedirect(t *testing.T) {
	srv := newFrontchannelHarness(t, false)
	idToken := fclLogin(t, srv)

	resp, err := nonFollowingClient().Get(srv.URL + "/end_session?id_token_hint=" + idToken)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status: got %d, want 204", resp.StatusCode)
	}
}

func TestFCL_DiscoveryAdvertisesWhenAnyClientOptsIn(t *testing.T) {
	srv := newFrontchannelHarness(t, true)
	resp, err := http.Get(srv.URL + sso.PathOIDCDiscovery)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if v, _ := doc["frontchannel_logout_supported"].(bool); !v {
		t.Fatalf("frontchannel_logout_supported: got %v, want true", doc["frontchannel_logout_supported"])
	}
	// sid claim is now plumbed through SessionManager-wired
	// deployments → session_supported flips true when the
	// front-channel base condition (any client with FCL URI)
	// holds. The harness wires a SessionManager so this MUST
	// be true.
	if v, _ := doc["frontchannel_logout_session_supported"].(bool); !v {
		t.Fatalf("frontchannel_logout_session_supported = %v want true (session manager wired)", doc["frontchannel_logout_session_supported"])
	}
}

func TestFCL_DiscoveryOmitsWhenNoClientOptsIn(t *testing.T) {
	srv := newFrontchannelHarness(t, false)
	resp, err := http.Get(srv.URL + sso.PathOIDCDiscovery)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if _, present := doc["frontchannel_logout_supported"]; present {
		t.Fatalf("frontchannel_logout_supported leaked into discovery: %v", doc["frontchannel_logout_supported"])
	}
}

// TestFCL_MultiRPFanOut proves the security.SubjectClientIndex-driven multi-
// RP variant: when the subject is signed into multiple FCL-capable
// clients, /end_session renders one hidden iframe per such client
// so every RP gets a chance to clear its own session. Without the
// index this would degrade to the single-iframe primary-only path
// — but the harness wires WithSubjectClientIndex so we exercise
// the fan-out branch.
func TestFCL_MultiRPFanOut(t *testing.T) {
	const (
		clientA      = "fcl-multi-a"
		clientB      = "fcl-multi-b"
		secretShared = "fcl-multi-secret"
		userID       = "u-multi"
		fcLogoutA    = "https://a.example/oidc/frontchannel-logout"
		fcLogoutB    = "https://b.example/oidc/frontchannel-logout"
		postLogout   = "https://a.example/post-logout"
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: userID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: clientA, Secret: secretShared, Active: true,
		AllowedAuthenticators:  []string{"password"},
		TokenStrategy:          "jwt",
		AllowedScopes:          []string{"openid"},
		PostLogoutRedirectURIs: []string{postLogout},
		FrontchannelLogoutURI:  fcLogoutA,
	})
	clients.AddSeed(&sso.Client{
		ID: clientB, Secret: secretShared, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedScopes:         []string{"openid"},
		FrontchannelLogoutURI: fcLogoutB,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: userID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	idx := defaultimpl.NewMemorySubjectClientIndex()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithIDTokenIssuer(issuer),
		sso.WithSubjectClientIndex(idx),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	defer httpSrv.Close()

	// Log into both clients so the security.SubjectClientIndex records each.
	login := func(cid string) string {
		body, _ := json.Marshal(map[string]any{
			"provider":   "password",
			"client_id":  cid,
			"credential": map[string]string{"username": "x", "password": "y"},
			"scope":      []string{"openid"},
		})
		resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login %s: %v", cid, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		id, _ := out["id_token"].(string)
		if id == "" {
			t.Fatalf("login %s no id_token: %s", cid, raw)
		}
		return id
	}
	idTokenA := login(clientA)
	_ = login(clientB)

	// /end_session with id_token_hint for client A. Expectation:
	// the rendered HTML carries BOTH iframes (A from the hint, B
	// from the index fan-out) so the user logs out everywhere.
	resp, err := nonFollowingClient().Get(httpSrv.URL + "/end_session?id_token_hint=" + idTokenA)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, fcLogoutA) {
		t.Errorf("primary iframe (client A) missing from FCL page: %s", s)
	}
	if !strings.Contains(s, fcLogoutB) {
		t.Errorf("fan-out iframe (client B) missing from FCL page — security.SubjectClientIndex not consulted: %s", s)
	}
	// Primary carries sid+iss; fan-out target carries iss only (sid
	// omitted because the security.SubjectClientIndex doesn't track per-
	// client session IDs).
	if !strings.Contains(s, `src="`+fcLogoutA+`?sid=`) {
		t.Errorf("primary iframe missing sid query: %s", s)
	}
	if strings.Contains(s, `src="`+fcLogoutB+`?sid=`) {
		t.Errorf("fan-out iframe should NOT carry sid: %s", s)
	}
}

func TestFCL_EscapesUntrustedRedirectComponents(t *testing.T) {
	srv := newFrontchannelHarness(t, true)
	idToken := fclLogin(t, srv)

	// State is the only attacker-controllable string that lands
	// inside the rendered URL. html/template's URL escaper for the
	// `href` and `content="url=..."` contexts MUST neutralize
	// quote/angle-bracket injection so a crafted state can't break
	// out of the attribute and inject script.
	u := srv.URL + "/end_session?id_token_hint=" + idToken +
		"&post_logout_redirect_uri=" + fclLoginURI +
		`&state=%22%3E%3Cscript%3Ealert(1)%3C/script%3E`
	resp, err := nonFollowingClient().Get(u)
	if err != nil {
		t.Fatalf("end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if strings.Contains(s, "<script>alert(1)</script>") {
		t.Fatalf("unescaped script tag in FCL page: %s", s)
	}
}
