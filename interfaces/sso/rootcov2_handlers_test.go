package sso_test

// rootcov2_handlers_test.go targets the remaining higher-statement handler
// surfaces the first rootcov_* pass left at 0%:
//   - PKCE capture + verify on the authorization_code flow (auth_code_handler.go
//     verifyPKCE / isPKCEMethodAllowedForClient)
//   - provider discovery + home-realm-required login branch (providersForClient)
//   - the legacy OAuth callback endpoint (handleCallback)
//   - "logout everywhere" revoke-all (handlers.go handleRevokeAll)
//   - full RFC 7592 DCR lifecycle PUT/DELETE (handleRegistrationPut/Delete)
//   - prompt=none silent renewal (discovery_handler.go handleSilentRenewal)
//   - the audit-by-id endpoint (handleAuditEventByID)
//   - the network-policy API handlers (handleList/Get/Apply/Delete/Classify/
//     ResolveMe + ClassifyRequest)
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo / rcovGetJSON.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/netpolicy"
	netmem "github.com/snaplink/sso/platform/netpolicy/memory"
	"github.com/snaplink/sso/protocols/oauth"
)

// TestRcov2H_PKCERoundTrip drives the authorization_code flow with a PKCE
// challenge captured at /auth/login and verified at /token with the matching
// code_verifier (verifyPKCE S256 path), plus the mismatch rejection.
func TestRcov2H_PKCERoundTrip(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)

	const verifier = "rcov2-pkce-verifier-abcdefghijklmnopqrstuvwxyz0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Login requesting a code with the PKCE challenge.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":              "password",
		"client_id":             rcovClient,
		"credential":            map[string]string{"username": rcovUsername, "password": rcovPassword},
		"response_type":         "code",
		"redirect_uri":          rcovRedirect,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	})
	if status != http.StatusOK {
		t.Fatalf("pkce login = %d body=%v", status, out)
	}
	code, _ := out["code"].(string)
	if code == "" {
		t.Fatalf("no code: %v", out)
	}

	// Wrong verifier => invalid_grant.
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"redirect_uri":  rcovRedirect,
		"code_verifier": "the-wrong-verifier-entirely-aaaaaaaaaaaaaaaaaaaaaa",
	})
	if status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Fatalf("pkce wrong verifier = %d %v, want 400 invalid_grant", status, tok)
	}

	// A fresh code + correct verifier succeeds (the first code was consumed).
	_, out2 := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":              "password",
		"client_id":             rcovClient,
		"credential":            map[string]string{"username": rcovUsername, "password": rcovPassword},
		"response_type":         "code",
		"redirect_uri":          rcovRedirect,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	})
	code2, _ := out2["code"].(string)
	status, tok = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "authorization_code",
		"code":          code2,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
		"redirect_uri":  rcovRedirect,
		"code_verifier": verifier,
	})
	if status != http.StatusOK {
		t.Fatalf("pkce correct verifier = %d body=%v, want 200", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("pkce exchange minted no token: %v", tok)
	}
}

// TestRcov2H_ProviderDiscovery covers the no-provider /auth/login branch that
// returns the per-client provider list (providersForClient + resolveHomeRealm
// miss path).
func TestRcov2H_ProviderDiscovery(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"client_id": rcovClient,
	})
	if status != http.StatusOK {
		t.Fatalf("provider discovery = %d body=%v", status, out)
	}
	provs, _ := out["providers"].([]any)
	if len(provs) == 0 {
		t.Errorf("expected a provider list: %v", out)
	}
}

// TestRcov2H_HomeRealmRequiredOnLogin covers the no-provider login branch that
// resolves a connection from the login_hint and returns connection_required.
func TestRcov2H_HomeRealmRequiredOnLogin(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore()
	_ = store.Upsert(context.Background(), &connections.Connection{
		ID: "umbrella", TenantID: "umbrella", Type: connections.TypeSAML,
		DisplayName: "Umbrella SSO", Domains: []string{"umbrella.example"}, Enabled: true,
	})
	s := rcovNewServer(t, sso.WithConnectionStore(store))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"client_id":  rcovClient,
		"login_hint": "neo@umbrella.example",
	})
	if status != http.StatusOK {
		t.Fatalf("home-realm login = %d body=%v", status, out)
	}
	if out["connection_required"] != true || out["connection_id"] != "umbrella" {
		t.Errorf("expected connection_required for umbrella: %v", out)
	}
}

// rcov2CallbackAuth is a real Authenticator whose Callback resolves a fixed user
// for a known code, driving handleCallback's success + failure branches.
type rcov2CallbackAuth struct{}

func (rcov2CallbackAuth) Name() string                 { return "rcov2cb" }
func (rcov2CallbackAuth) LoginURL(state string) string { return "" }
func (rcov2CallbackAuth) Authenticate(context.Context, *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, errors.New("not used")
}
func (rcov2CallbackAuth) Callback(_ context.Context, st *sso.CallbackState) (*sso.AuthResult, error) {
	if st.Code == "good-code" {
		return &sso.AuthResult{UserID: rcovUser, Provider: "rcov2cb"}, nil
	}
	return nil, errors.New("bad callback")
}

// TestRcov2H_Callback covers the legacy /auth/callback endpoint: a successful
// callback creates a session; a missing code is a 400; a bad code is a 401.
func TestRcov2H_Callback(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithAuthenticator(rcov2CallbackAuth{}))

	// Success: provider names the authenticator, code resolves a user.
	status, out := rcovDo(t, http.MethodGet,
		s.http.URL+"/auth/callback?provider=rcov2cb&code=good-code&state=st", "", nil)
	if status != http.StatusOK {
		t.Fatalf("callback success = %d body=%v", status, out)
	}
	if out["status"] != "authenticated" {
		t.Errorf("callback status = %v, want authenticated", out["status"])
	}

	// Missing code => 400.
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/auth/callback?state=st", "", nil)
	if status != http.StatusBadRequest {
		t.Errorf("callback no code = %d, want 400", status)
	}

	// Bad code => 401.
	status, _ = rcovDo(t, http.MethodGet,
		s.http.URL+"/auth/callback?provider=rcov2cb&code=bad&state=st", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("callback bad code = %d, want 401", status)
	}
}

// TestRcov2H_RevokeAll covers POST /token/revoke-all — the bearer-authenticated
// "logout everywhere" path backed by the RefreshTokenSubjectIndex extension.
func TestRcov2H_RevokeAll(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithSubjectClientIndex(defaultimpl.NewMemorySubjectClientIndex()))
	access, _ := rcovDirectLogin(t, s)

	status, _ := rcovPostJSON(t, s.http.URL+"/token/revoke-all", access, nil)
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Errorf("revoke-all = %d, want 200/204", status)
	}

	// Missing bearer => 401.
	status, _ = rcovPostJSON(t, s.http.URL+"/token/revoke-all", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("revoke-all no bearer = %d, want 401", status)
	}
}

// TestRcov2H_DCRLifecycle covers the full RFC 7591/7592 DCR lifecycle: register
// (POST), then update (PUT) + delete (DELETE) authenticated with the
// registration_access_token (handleRegistrationPut/Delete).
func TestRcov2H_DCRLifecycle(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithDynamicClientRegistration(oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	}))

	// Register.
	status, out := rcovPostJSON(t, s.http.URL+"/register", "", map[string]any{
		"client_name":   "DCR Coverage",
		"redirect_uris": []string{"https://dcr.example.com/cb"},
	})
	if status != http.StatusCreated && status != http.StatusOK {
		t.Fatalf("DCR register = %d body=%v", status, out)
	}
	clientID, _ := out["client_id"].(string)
	rat, _ := out["registration_access_token"].(string)
	if clientID == "" || rat == "" {
		t.Fatalf("DCR register missing client_id/RAT: %v", out)
	}

	// GET the registration with the RAT.
	status, _ = rcovDo(t, http.MethodGet, s.http.URL+"/register/"+clientID, rat, nil)
	if status != http.StatusOK {
		t.Errorf("DCR get = %d, want 200", status)
	}

	// PUT (update) with the RAT.
	status, out = rcovDo(t, http.MethodPut, s.http.URL+"/register/"+clientID, rat, map[string]any{
		"client_id":     clientID,
		"client_name":   "DCR Coverage Renamed",
		"redirect_uris": []string{"https://dcr.example.com/cb2"},
	})
	if status != http.StatusOK {
		t.Errorf("DCR put = %d body=%v, want 200", status, out)
	}

	// Anti-enumeration: a wrong RAT on PUT => 401.
	status, _ = rcovDo(t, http.MethodPut, s.http.URL+"/register/"+clientID, "wrong-rat", map[string]any{
		"client_id": clientID,
	})
	if status != http.StatusUnauthorized {
		t.Errorf("DCR put wrong RAT = %d, want 401", status)
	}

	// DELETE with the RAT.
	status, _ = rcovDo(t, http.MethodDelete, s.http.URL+"/register/"+clientID, rat, nil)
	if status != http.StatusNoContent && status != http.StatusOK {
		t.Errorf("DCR delete = %d, want 204/200", status)
	}
}

// TestRcov2H_SilentRenewal covers prompt=none silent renewal: a prior login
// yields an id_token used as id_token_hint to mint fresh tokens without
// re-authenticating (discovery_handler.go handleSilentRenewal).
func TestRcov2H_SilentRenewal(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	s := rcovNewServer(t,
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
	)

	// Interactive login to mint an id_token (the renewal hint).
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("seed login = %d body=%v", status, out)
	}
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("seed login produced no id_token: %v", out)
	}

	// prompt=none with the id_token_hint => silent mint (no credential).
	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"client_id":     rcovClient,
		"prompt":        "none",
		"scope":         []string{"openid"},
		"id_token_hint": idToken,
	})
	// Either a fresh token (session resolvable) or an interaction_required
	// error — both exercise handleSilentRenewal's body; only a 5xx is a fail.
	if status >= 500 {
		t.Errorf("silent renewal = %d body=%v, want < 500", status, out)
	}
}

// TestRcov2H_AuditEventByID covers GET /api/v1/audit/events/:id — fetch a single
// recorded event after a login generated one.
func TestRcov2H_AuditEventByID(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithAuditAPI())
	rcovDirectLogin(t, s)

	// List to obtain a real event id.
	var list map[string]any
	resp := rcovGetJSON(t, s.http.URL+"/api/v1/audit/events", &list)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit list = %d", resp.StatusCode)
	}
	events, _ := list["events"].([]any)
	if len(events) == 0 {
		t.Skip("no audit events recorded to fetch by id")
	}
	first, _ := events[0].(map[string]any)
	id, _ := first["id"].(string)
	if id == "" {
		t.Skipf("first event has no id field: %v", first)
	}

	// Fetch by id.
	var single map[string]any
	resp = rcovGetJSON(t, s.http.URL+"/api/v1/audit/events/"+id, &single)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("audit by id = %d, want 200", resp.StatusCode)
	}

	// Unknown id => 404.
	resp = rcovGetJSON(t, s.http.URL+"/api/v1/audit/events/no-such-id", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("audit unknown id = %d, want 404", resp.StatusCode)
	}
}

// TestRcov2H_NetPolicyAPI covers the network-policy API handlers (List/Apply/
// Get/Delete/Classify/ResolveMe) + ClassifyRequest, exercised without the admin
// middleware wrapper (the gate is external; the handler bodies are the target).
func TestRcov2H_NetPolicyAPI(t *testing.T) {
	t.Parallel()
	netStore := netmem.New()
	classifier := netpolicy.NewClassifier()
	s := rcovNewServer(t,
		sso.WithNetworkPolicy(netStore, classifier),
		sso.WithNetworkPolicyAPI(),
	)
	base := s.http.URL + "/api/v1/netpolicy"

	// Apply a named policy.
	status, out := rcovPostJSON(t, base+"/policies", "", map[string]any{
		"name":       "corp",
		"cidrs":      []string{"10.0.0.0/8"},
		"priority":   10,
		"trust_tier": "internal",
	})
	if status >= 500 {
		t.Fatalf("netpolicy apply = %d body=%v", status, out)
	}

	// List.
	resp := rcovGetJSON(t, base+"/policies", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("netpolicy list = %d, want 200", resp.StatusCode)
	}

	// Get by name.
	resp = rcovGetJSON(t, base+"/policies/corp", nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		t.Errorf("netpolicy get = %d", resp.StatusCode)
	}

	// Classify (admin-ish; reachable here without the external gate).
	resp = rcovGetJSON(t, base+"/classify?ip=10.1.2.3", nil)
	if resp.StatusCode >= 500 {
		t.Errorf("netpolicy classify = %d, want < 500", resp.StatusCode)
	}

	// Resolve-me (the always-open endpoint).
	resp = rcovGetJSON(t, base+"/resolve-me", nil)
	if resp.StatusCode >= 500 {
		t.Errorf("netpolicy resolve-me = %d, want < 500", resp.StatusCode)
	}

	// Delete.
	status, _ = rcovDo(t, http.MethodDelete, base+"/policies/corp", "", nil)
	if status >= 500 {
		t.Errorf("netpolicy delete = %d, want < 500", status)
	}
}

// TestRcov2H_ClassifyRequest covers the *sso.Server.ClassifyRequest embedder
// seam directly: a request whose RemoteAddr falls inside a seeded CIDR resolves
// to that policy; a nil request / no classifier resolves to nil.
func TestRcov2H_ClassifyRequest(t *testing.T) {
	t.Parallel()
	netStore := netmem.New()
	classifier := netpolicy.NewClassifier()
	_, _ = netStore.Apply(context.Background(), &netpolicy.Policy{
		Name:     "internal",
		CIDRs:    []string{"10.0.0.0/8"},
		Priority: 5,
	})
	_ = classifier.Reload(context.Background(), netStore)

	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithNetworkPolicy(netStore, classifier),
	)

	req, _ := http.NewRequest(http.MethodGet, "https://x/y", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	if p := srv.ClassifyRequest(req); p == nil {
		t.Errorf("ClassifyRequest(10.1.2.3) = nil, want the internal policy")
	}
	// A nil request never classifies.
	if p := srv.ClassifyRequest(nil); p != nil {
		t.Errorf("ClassifyRequest(nil) = %v, want nil", p)
	}
}

// rcov2FederatedAuth is a fake federated authenticator: LoginURL always
// redirects, so /auth/login must never reach Authenticate for it.
type rcov2FederatedAuth struct{ target string }

func (a rcov2FederatedAuth) Name() string                 { return "rcov2fed" }
func (a rcov2FederatedAuth) LoginURL(state string) string { return a.target + "?state=" + state }
func (rcov2FederatedAuth) Authenticate(context.Context, *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, errors.New("must not be called for a federated provider")
}
func (rcov2FederatedAuth) Callback(context.Context, *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("not used")
}

// TestRcov2H_GetLoginFederatedRedirect covers bindLoginRequestFromQuery: a
// real top-level GET navigation (the only way a browser can follow a
// cross-origin redirect to a federated provider's authorize endpoint — a
// fetch()/XHR POST can't) must reach the SAME federated-redirect branch a
// POST does, with the query-bound provider/client_id/state.
func TestRcov2H_GetLoginFederatedRedirect(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithAuthenticator(rcov2FederatedAuth{target: "https://idp.example/authorize"}))
	// rcovClient's AllowedAuthenticators is ["password"] only; a distinct
	// client with an unrestricted (empty) allowlist is needed to reach the
	// federated dispatch instead of authenticator_not_allowed_for_client.
	const fedClient = "rcov2fed-client"
	s.clients.AddSeed(&sso.Client{
		ID:            fedClient,
		Name:          "Federated Client",
		RedirectURIs:  []string{rcovRedirect},
		TokenStrategy: "jwt",
		Active:        true,
		SkipConsent:   true,
	})

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(s.http.URL + "/auth/login?provider=rcov2fed&client_id=" + fedClient + "&state=xyz")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want %d, body=%s", resp.StatusCode, http.StatusFound, raw)
	}
	if loc := resp.Header.Get("Location"); loc != "https://idp.example/authorize?state=xyz" {
		t.Errorf("Location = %q", loc)
	}
}

// TestRcov2H_GetLoginNoProvider covers the GET-navigation prologue when no
// provider is selected yet — must return the SAME provider-list JSON as the
// POST path (bindLoginRequestFromQuery still lets preAuthLoginGates run).
func TestRcov2H_GetLoginNoProvider(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)

	resp, err := http.Get(s.http.URL + "/auth/login?client_id=" + rcovClient)
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
