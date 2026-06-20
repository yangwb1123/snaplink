package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oauth"
)

// This suite locks the RFC 6749 §3.3 scope-authorization gate
// (oauth.GrantedScopes) end-to-end across every issuance entry. Three
// clients exercise the three branches:
//
//   - scClientRestricted  AllowedScopes=["api:read"]   — validate/default
//   - scClientOpenID      AllowedScopes=["profile"]    — openid-always-allowed
//   - scClientUnrestricted AllowedScopes=nil           — backward-compat
//
// The unrestricted client is the byte-identical proof: with no allowlist
// it gets whatever scope it asks for, exactly as before the gate existed.
const (
	scUser             = "u-sc"
	scClientRestricted = "sc-restricted"
	scClientOpenID     = "sc-openid"
	scClientUnrestrict = "sc-unrestricted"
	scSecret           = "sc-secret"
	scDeviceCodeTTL    = 5 * time.Minute
	scDevicePollInter  = time.Millisecond
)

type scopeHarness struct {
	srv     *httptest.Server
	devices oauth.DeviceCodeStore
	ciba    oauth.CIBAStore
}

func newScopeHarness(t *testing.T) *scopeHarness {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: scUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: scClientRestricted, Secret: scSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedScopes:         []string{"api:read"},
		RedirectURIs:          []string{"https://rp.example/cb"},
	})
	clients.AddSeed(&sso.Client{
		ID: scClientOpenID, Secret: scSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedScopes:         []string{"profile"},
	})
	clients.AddSeed(&sso.Client{
		ID: scClientUnrestrict, Secret: scSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		// nil AllowedScopes ⇒ unrestricted
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: scUser, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	devices := defaultimpl.NewMemoryDeviceCodeStore()
	cibaStore := defaultimpl.NewMemoryCIBAStore()
	cibaTransport := oauth.CIBATransportFunc(func(_ context.Context, _, _ string, _ map[string]string) error { return nil })

	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithIDTokenIssuer(issuer),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), time.Hour),
		sso.WithDeviceCodeStore(devices, scDeviceCodeTTL, scDevicePollInter, ""),
		sso.WithCIBA(cibaStore, cibaTransport, 2*time.Minute, scDevicePollInter),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &scopeHarness{srv: httpSrv, devices: devices, ciba: cibaStore}
}

func scPostJSON(t *testing.T, srv *httptest.Server, path string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func scPostForm(t *testing.T, srv *httptest.Server, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// ---------- login direct-mint ----------

func TestScope_LoginDirectMint_InAllowlist(t *testing.T) {
	h := newScopeHarness(t)
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientRestricted,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"api:read"},
	})
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("response scope = %v want api:read", out["scope"])
	}
	if sc := jwtPayloadField(t, out["access_token"].(string), "scope"); sc != "api:read" {
		t.Fatalf("jwt scope = %v want api:read", sc)
	}
}

func TestScope_LoginDirectMint_OutOfAllowlistRejected(t *testing.T) {
	h := newScopeHarness(t)
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientRestricted,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"api:read", "api:write"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", code, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
	// RFC 9207 iss MUST ride on every /auth/login response, including
	// this authz error.
	if out["iss"] == nil || out["iss"] == "" {
		t.Fatalf("expected iss on authz error, got %v", out["iss"])
	}
}

func TestScope_LoginDirectMint_EmptyDefaultsToAllowlist(t *testing.T) {
	h := newScopeHarness(t)
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientRestricted,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		// no scope → default to AllowedScopes (["api:read"])
	})
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("default scope = %v want api:read", out["scope"])
	}
}

func TestScope_LoginDirectMint_OpenIDAlwaysAllowed(t *testing.T) {
	h := newScopeHarness(t)
	// AllowedScopes=["profile"]; "openid profile" is permitted (openid
	// bypasses the allowlist as the OIDC trigger).
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientOpenID,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"openid", "profile"},
	})
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, out)
	}
	if out["scope"] != "openid profile" {
		t.Fatalf("scope = %v want 'openid profile'", out["scope"])
	}
}

func TestScope_LoginDirectMint_OpenIDPlusDisallowedRejected(t *testing.T) {
	h := newScopeHarness(t)
	// "openid email" — openid is fine but email is not in ["profile"].
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientOpenID,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"openid", "email"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", code, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
}

// Backward-compat byte-identical proof: a client with NO allowlist gets
// whatever scope it requests, unchanged.
func TestScope_LoginDirectMint_UnrestrictedPassthrough(t *testing.T) {
	h := newScopeHarness(t)
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientUnrestrict,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"anything", "whatever:write"},
	})
	if code != http.StatusOK {
		t.Fatalf("status=%d body=%v", code, out)
	}
	if out["scope"] != "anything whatever:write" {
		t.Fatalf("scope = %v want pass-through 'anything whatever:write'", out["scope"])
	}
	if sc := jwtPayloadField(t, out["access_token"].(string), "scope"); sc != "anything whatever:write" {
		t.Fatalf("jwt scope = %v want pass-through", sc)
	}
}

// ---------- authorization_code (login → /token) ----------

func scAuthCode(t *testing.T, srv *httptest.Server, clientID string, scope []string) string {
	t.Helper()
	body := map[string]any{
		"provider":      "password",
		"client_id":     clientID,
		"response_type": "code",
		"redirect_uri":  "https://rp.example/cb",
		"credential":    map[string]string{"username": "x", "password": "y"},
	}
	if scope != nil {
		body["scope"] = scope
	}
	code, out := scPostJSON(t, srv, "/auth/login", body)
	if code != http.StatusOK {
		t.Fatalf("authcode login status=%d body=%v", code, out)
	}
	c, _ := out["code"].(string)
	if c == "" {
		t.Fatalf("no code in %v", out)
	}
	return c
}

func TestScope_AuthCode_GrantedScopeBakedIntoCode(t *testing.T) {
	h := newScopeHarness(t)
	// Request nothing → code carries the defaulted allowlist scope.
	code := scAuthCode(t, h.srv, scClientRestricted, nil)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		"redirect_uri":  {"https://rp.example/cb"},
	}
	st, out := scPostForm(t, h.srv, "/token", form)
	if st != http.StatusOK {
		t.Fatalf("token status=%d body=%v", st, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("token scope = %v want api:read (defaulted at login)", out["scope"])
	}
	if sc := jwtPayloadField(t, out["access_token"].(string), "scope"); sc != "api:read" {
		t.Fatalf("jwt scope = %v want api:read", sc)
	}
}

func TestScope_AuthCode_OutOfAllowlistRejectedAtLogin(t *testing.T) {
	h := newScopeHarness(t)
	// The gate fires at /auth/login BEFORE a code is ever issued.
	code, out := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientRestricted,
		"response_type": "code",
		"redirect_uri":  "https://rp.example/cb",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"api:write"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", code, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
}

// ---------- client_credentials ----------

func TestScope_ClientCredentials_InAllowlist(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		"scope":         {"api:read"},
	})
	if st != http.StatusOK {
		t.Fatalf("status=%d body=%v", st, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("scope = %v want api:read", out["scope"])
	}
}

func TestScope_ClientCredentials_OutOfAllowlistRejected(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		"scope":         {"api:read api:write"},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", st, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
}

func TestScope_ClientCredentials_EmptyDefaultsToAllowlist(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		// no scope → default to AllowedScopes
	})
	if st != http.StatusOK {
		t.Fatalf("status=%d body=%v", st, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("default scope = %v want api:read", out["scope"])
	}
}

func TestScope_ClientCredentials_UnrestrictedPassthrough(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {scClientUnrestrict},
		"client_secret": {scSecret},
		"scope":         {"anything"},
	})
	if st != http.StatusOK {
		t.Fatalf("status=%d body=%v", st, out)
	}
	if out["scope"] != "anything" {
		t.Fatalf("scope = %v want pass-through anything", out["scope"])
	}
}

// ---------- device_code ----------

func scDeviceAuth(t *testing.T, srv *httptest.Server, clientID string, scope string) (int, map[string]any) {
	t.Helper()
	form := url.Values{"client_id": {clientID}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return scPostForm(t, srv, "/device/code", form)
}

func TestScope_Device_OutOfAllowlistRejectedAtRequest(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scDeviceAuth(t, h.srv, scClientRestricted, "api:write")
	if st != http.StatusBadRequest {
		t.Fatalf("device auth status=%d want 400 body=%v", st, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
}

func TestScope_Device_GrantedScopeFlowsToToken(t *testing.T) {
	h := newScopeHarness(t)
	// Request nothing → device code carries defaulted allowlist scope.
	st, out := scDeviceAuth(t, h.srv, scClientRestricted, "")
	if st != http.StatusOK {
		t.Fatalf("device auth status=%d body=%v", st, out)
	}
	deviceCode, _ := out["device_code"].(string)
	if deviceCode == "" {
		t.Fatalf("no device_code: %v", out)
	}
	// Approve out of band.
	dc, err := h.devices.GetByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("get device code: %v", err)
	}
	if err := h.devices.Approve(context.Background(), dc.UserCode, scUser, "password", nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Poll /token — wait out the (tiny) interval.
	time.Sleep(2 * scDevicePollInter)
	st, tok := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code":   {deviceCode},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
	})
	if st != http.StatusOK {
		t.Fatalf("device token status=%d body=%v", st, tok)
	}
	if tok["scope"] != "api:read" {
		t.Fatalf("device token scope = %v want api:read", tok["scope"])
	}
}

func TestScope_Device_UnrestrictedPassthrough(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scDeviceAuth(t, h.srv, scClientUnrestrict, "anything")
	if st != http.StatusOK {
		t.Fatalf("device auth status=%d body=%v", st, out)
	}
	if out["device_code"] == nil {
		t.Fatalf("expected device_code for unrestricted client: %v", out)
	}
}

// ---------- CIBA ----------

func TestScope_CIBA_OutOfAllowlistRejectedAtRequest(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scPostForm(t, h.srv, "/backchannel-authentication", url.Values{
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		"login_hint":    {scUser},
		"scope":         {"api:write"},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("ciba auth status=%d want 400 body=%v", st, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
}

func TestScope_CIBA_GrantedScopeFlowsToToken(t *testing.T) {
	h := newScopeHarness(t)
	st, out := scPostForm(t, h.srv, "/backchannel-authentication", url.Values{
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		"login_hint":    {scUser},
		"scope":         {"api:read"},
	})
	if st != http.StatusOK {
		t.Fatalf("ciba auth status=%d body=%v", st, out)
	}
	authReqID, _ := out["auth_req_id"].(string)
	if authReqID == "" {
		t.Fatalf("no auth_req_id: %v", out)
	}
	if err := h.ciba.SetStatus(context.Background(), authReqID, oauth.CIBAApproved); err != nil {
		t.Fatalf("approve ciba: %v", err)
	}
	time.Sleep(2 * scDevicePollInter)
	st, tok := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {oauth.GrantCIBA},
		"auth_req_id":   {authReqID},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
	})
	if st != http.StatusOK {
		t.Fatalf("ciba token status=%d body=%v", st, tok)
	}
	if tok["scope"] != "api:read" {
		t.Fatalf("ciba token scope = %v want api:read", tok["scope"])
	}
}

// ---------- token-exchange (subset AND allowlist intersection) ----------

func TestScope_TokenExchange_BoundedByAllowlist(t *testing.T) {
	h := newScopeHarness(t)
	// Mint a subject token via the unrestricted client carrying a broad
	// scope the restricted downstream client is NOT entitled to.
	_, login := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientUnrestrict,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"api:read", "api:write"},
	})
	subject, _ := login["access_token"].(string)
	if subject == "" {
		t.Fatalf("no subject token: %v", login)
	}

	// Exchange requesting "api:write" — ⊆ subject_token, but NOT in the
	// downstream client's AllowedScopes=["api:read"] → invalid_scope.
	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {scClientRestricted},
		"client_secret":      {scSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"api:write"},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("exchange status=%d want 400 body=%v", st, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}

	// Exchange requesting "api:read" — ⊆ subject_token AND ⊆ allowlist.
	st, out = scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {scClientRestricted},
		"client_secret":      {scSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"api:read"},
	})
	if st != http.StatusOK {
		t.Fatalf("exchange status=%d body=%v", st, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("exchange scope = %v want api:read", out["scope"])
	}
}

// Token-exchange subset rule still governs independently of the allowlist
// (the downstream client is unrestricted here, so only the subject-subset
// bound applies — proving the new gate doesn't loosen §2.1).
func TestScope_TokenExchange_SubsetStillEnforced(t *testing.T) {
	h := newScopeHarness(t)
	_, login := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":      "password",
		"client_id":     scClientUnrestrict,
		"response_type": "token",
		"credential":    map[string]string{"username": "x", "password": "y"},
		"scope":         []string{"api:read"},
	})
	subject, _ := login["access_token"].(string)

	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {scClientUnrestrict},
		"client_secret":      {scSecret},
		"subject_token":      {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":              {"api:read api:write"}, // expansion beyond subject → reject
	})
	if st != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", st, out)
	}
	if out["error"] != sso.ErrInvalidScope {
		t.Fatalf("error = %v want invalid_scope", out["error"])
	}
}

// ---------- refresh keeps RFC 6749 §6 (no allowlist re-check) ----------

// A refresh narrows within the originally-granted scope. The original
// scope was authorized at first issuance; refresh does NOT re-check
// against AllowedScopes (RFC 6749 §6 only requires ⊆ original).
func TestScope_Refresh_KeepsSubsetSemantics(t *testing.T) {
	h := newScopeHarness(t)
	// First issuance via login (defaults to ["api:read"]).
	_, login := scPostJSON(t, h.srv, "/auth/login", map[string]any{
		"provider":   "password",
		"client_id":  scClientRestricted,
		"credential": map[string]string{"username": "x", "password": "y"},
		"scope":      []string{"api:read"},
	})
	refresh, _ := login["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh token: %v", login)
	}
	// Refresh keeping the same scope succeeds.
	st, out := scPostForm(t, h.srv, "/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {scClientRestricted},
		"client_secret": {scSecret},
		"scope":         {"api:read"},
	})
	if st != http.StatusOK {
		t.Fatalf("refresh status=%d body=%v", st, out)
	}
	if out["scope"] != "api:read" {
		t.Fatalf("refresh scope = %v want api:read", out["scope"])
	}
}
