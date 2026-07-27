package ssotest

import "github.com/yangwb1123/snaplink/protocols/oauth"

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	cpUserID   = "u-claims"
	cpClientID = "claims-client"
	cpSecret   = "claims-secret"
	cpPassword = "pw"
	cpRedirect = "https://app.example/cb"
)

// claimsCaptureAuthenticator records the AuthRequest.RequestedClaims
// payload so tests can verify it threaded through from /auth/login
// + PAR + JAR.
type claimsCaptureAuthenticator struct {
	mu     sync.Mutex
	claims json.RawMessage
}

func (c *claimsCaptureAuthenticator) Name() string             { return "password" }
func (c *claimsCaptureAuthenticator) LoginURL(_ string) string { return "" }
func (c *claimsCaptureAuthenticator) Authenticate(_ context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	if req == nil {
		return nil, errors.New("nil")
	}
	c.mu.Lock()
	c.claims = append(json.RawMessage(nil), req.RequestedClaims...)
	c.mu.Unlock()
	return &sso.AuthResult{UserID: cpUserID, Provider: "password"}, nil
}
func (c *claimsCaptureAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("no callback")
}
func (c *claimsCaptureAuthenticator) snapshot() json.RawMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.claims == nil {
		return nil
	}
	out := make(json.RawMessage, len(c.claims))
	copy(out, c.claims)
	return out
}

func newClaimsParamHarness(t *testing.T) (*httptest.Server, *claimsCaptureAuthenticator, oauth.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cpUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cpClientID, Secret: cpSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{cpRedirect},
	})
	auth := &claimsCaptureAuthenticator{}
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, auth, parStore
}

func TestClaimsParam_AcceptedAndThreaded(t *testing.T) {
	srv, auth, _ := newClaimsParamHarness(t)
	// This verifies the claims parameter is parsed and threaded to the
	// authenticator with both branches intact. The id_token.acr request is
	// now ENFORCED (the AS must achieve the requested ACR — see TestClaimsACR_*),
	// so this threading test uses a non-enforced id_token claim to keep both
	// sections present without tripping the ACR gate.
	claims := `{"userinfo":{"email":null,"name":{"essential":true}},"id_token":{"email":null}}`
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(claims),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	got := auth.snapshot()
	if len(got) == 0 {
		t.Fatalf("authenticator saw no RequestedClaims")
	}
	// Round-trip through a generic decode to confirm shape preserved.
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("requested claims not parseable: %v", err)
	}
	if _, ok := parsed["userinfo"].(map[string]any); !ok {
		t.Errorf("userinfo branch missing: %v", parsed)
	}
	if _, ok := parsed["id_token"].(map[string]any); !ok {
		t.Errorf("id_token branch missing: %v", parsed)
	}
}

func TestClaimsParam_RejectsNonObject(t *testing.T) {
	srv, _, _ := newClaimsParamHarness(t)
	// JSON array, not an object → MUST be rejected per §5.5.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`["not", "an", "object"]`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["error"] != sso.ErrInvalidRequest {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidRequest)
	}
}

func TestClaimsParam_RejectsInnerNonObject(t *testing.T) {
	// `userinfo` MUST itself be a JSON object per §5.5.
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"userinfo": "not-an-object"}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestClaimsParam_RejectsTypoedEssentialBool(t *testing.T) {
	// The classic RP misconfig: `{"essential": "true"}` (string)
	// instead of `{"essential": true}` (bool). The old validator
	// silently accepted any inner JSON; the new one rejects so
	// the RP sees the bug immediately instead of debugging "why
	// is my essential claim being ignored".
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"userinfo": {"email": {"essential": "true"}}}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 on essential=\"true\" typo", resp.StatusCode)
	}
}

func TestClaimsParam_RejectsValuesNotAnArray(t *testing.T) {
	// `values` MUST be an array per §5.5.1. RP passing a scalar
	// is a typo for `value` (singular) — surface it.
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"id_token": {"acr": {"values": "level-2"}}}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 on values=string", resp.StatusCode)
	}
}

func TestClaimsParam_AcceptsNullPerSpec(t *testing.T) {
	// `{"email": null}` is the canonical "just request this claim,
	// no constraints" shape. MUST be accepted.
	srv, _, _ := newClaimsParamHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  cpClientID,
		"credential": map[string]string{"username": cpUserID, "password": cpPassword},
		"claims":     json.RawMessage(`{"userinfo": {"email": null, "name": {"essential": true}}}`),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 on valid mixed shape", resp.StatusCode)
	}
}

func TestClaimsParam_PARPushSurvives(t *testing.T) {
	srv, auth, store := newClaimsParamHarness(t)
	uri, _ := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:    cpClientID,
		RedirectURI: cpRedirect,
		Claims:      json.RawMessage(`{"userinfo":{"email":null}}`),
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   cpClientID,
		"credential":  map[string]string{"username": cpUserID, "password": cpPassword},
		"request_uri": uri,
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	_ = resp.Body.Close()
	got := auth.snapshot()
	if len(got) == 0 {
		t.Fatalf("RequestedClaims not threaded from PAR")
	}
	var parsed map[string]any
	_ = json.Unmarshal(got, &parsed)
	if _, ok := parsed["userinfo"].(map[string]any); !ok {
		t.Errorf("PAR-pushed userinfo branch lost: %v", parsed)
	}
}

// newClaimsCodeFlowServer wires the authorization_code round trip with an
// id_token issuer and an authenticator that returns multiple attributes, so
// tests can prove the OIDC Core §5.5 claims parameter survives the code
// round trip (login → code → /token) instead of only the direct-mint path.
func newClaimsCodeFlowServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cpUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cpClientID, Secret: cpSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{cpRedirect},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == cpUserID && p == cpPassword {
				return &sso.AuthResult{
					UserID: cpUserID,
					Attributes: map[string]string{
						"email": "alice@example.com",
						"name":  "Alice",
						"role":  "admin",
					},
				}, nil
			}
			return nil, errors.New("bad credentials")
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
		sso.WithIDTokenIssuer(issuer),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// claimsCodeFlow drives /auth/login (response_type=code, scope=openid, the
// supplied claims parameter) then exchanges the code at /token, returning the
// exchange response body.
func claimsCodeFlow(t *testing.T, srv *httptest.Server, claims json.RawMessage) map[string]any {
	t.Helper()
	login := map[string]any{
		"provider":      "password",
		"client_id":     cpClientID,
		"credential":    map[string]string{"username": cpUserID, "password": cpPassword},
		"response_type": "code",
		"redirect_uri":  cpRedirect,
		"scope":         []string{"openid"},
	}
	if len(claims) > 0 {
		login["claims"] = claims
	}
	body, _ := json.Marshal(login)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, raw)
	}
	var loginOut map[string]any
	_ = json.Unmarshal(raw, &loginOut)
	code, _ := loginOut["code"].(string)
	if code == "" {
		t.Fatalf("no code in login response: %s", raw)
	}
	body, _ = json.Marshal(map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     cpClientID,
		"client_secret": cpSecret,
		"redirect_uri":  cpRedirect,
	})
	resp, err = http.Post(srv.URL+"/token", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

// jwtPayloadClaims decodes a compact JWT's payload segment without verifying
// the signature (tests only inspect claim presence).
func jwtPayloadClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

// TestClaimsParam_AuthCodeRoundTripProjectsIDToken closes the §5.5 gap on the
// authorization_code path: the claims parameter captured at /auth/login must
// survive the code round trip so the /token-minted id_token carries ONLY the
// requested claims (email — not name/role), exactly like the direct-mint flow.
func TestClaimsParam_AuthCodeRoundTripProjectsIDToken(t *testing.T) {
	srv := newClaimsCodeFlowServer(t)
	claims := json.RawMessage(`{"id_token":{"email":null},"userinfo":{"email":null}}`)
	out := claimsCodeFlow(t, srv, claims)

	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in exchange response: %v", out)
	}
	ext := idTokenExtraClaims(t, idToken)
	if got, _ := ext["email"].(string); got != "alice@example.com" {
		t.Errorf("id_token email = %v, want alice@example.com (requested claim dropped)", ext["email"])
	}
	if _, ok := ext["name"]; ok {
		t.Errorf("id_token carries unrequested claim name: %v", ext["name"])
	}
	if _, ok := ext["role"]; ok {
		t.Errorf("id_token carries unrequested claim role: %v", ext["role"])
	}
}

// idTokenExtraClaims returns the Ed25519 issuer's `ext` claim object — where
// attribute-sourced claims (email, name, ...) ride on its id_tokens.
func idTokenExtraClaims(t *testing.T, idToken string) map[string]any {
	t.Helper()
	ext, _ := jwtPayloadClaims(t, idToken)["ext"].(map[string]any)
	return ext
}

// TestClaimsParam_AuthCodeRoundTripStampsAccessToken proves the exchange-
// minted access token carries the claims parameter (the `_claims_` claim the
// Ed25519 issuer round-trips into TokenClaims.RequestedClaims) so /userinfo
// can project the RP-requested claims after a code flow.
func TestClaimsParam_AuthCodeRoundTripStampsAccessToken(t *testing.T) {
	srv := newClaimsCodeFlowServer(t)
	claims := json.RawMessage(`{"userinfo":{"email":null,"name":{"essential":true}}}`)
	out := claimsCodeFlow(t, srv, claims)

	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in exchange response: %v", out)
	}
	atClaims := jwtPayloadClaims(t, access)
	carried, ok := atClaims["_claims_"]
	if !ok {
		t.Fatalf("access token missing _claims_ (RequestedClaims not threaded through the code): %v", atClaims)
	}
	var want, got any
	_ = json.Unmarshal(claims, &want)
	blob, _ := json.Marshal(carried)
	_ = json.Unmarshal(blob, &got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("access token _claims_ = %v, want %v", carried, want)
	}
}

// TestClaimsParam_AuthCodeNoClaimsUnchanged is the regression guard: a code
// flow WITHOUT a claims parameter must behave exactly as before the carry —
// no _claims_ claim on the access token and an UNPROJECTED id_token carrying
// every attribute.
func TestClaimsParam_AuthCodeNoClaimsUnchanged(t *testing.T) {
	srv := newClaimsCodeFlowServer(t)
	out := claimsCodeFlow(t, srv, nil)

	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in exchange response: %v", out)
	}
	if _, ok := jwtPayloadClaims(t, access)["_claims_"]; ok {
		t.Errorf("access token carries _claims_ without a claims parameter")
	}
	idToken, _ := out["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in exchange response: %v", out)
	}
	ext := idTokenExtraClaims(t, idToken)
	for _, name := range []string{"email", "name", "role"} {
		if _, ok := ext[name]; !ok {
			t.Errorf("id_token lost attribute %q on the no-claims path (projection fired without a request)", name)
		}
	}
}

func TestClaimsParam_DiscoveryAdvertises(t *testing.T) {
	srv, _, _ := newClaimsParamHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if v, _ := doc["claims_parameter_supported"].(bool); !v {
		t.Errorf("claims_parameter_supported = %v want true", doc["claims_parameter_supported"])
	}
}
