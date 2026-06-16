package sso_test

// rootcov2_extensions_test.go targets the higher-statement extension surfaces
// the first rootcov_* pass left at 0%:
//   - device-code APPROVAL + poll grant (device_code_handler.go handleDeviceVerify
//     + handleDeviceTokenGrant) — the first pass only started a device flow
//   - B2B home-realm discovery (home_realm.go)
//   - OpenID Federation 1.0 entity config (federation_handler.go BuildOPMetadata
//     + handleFederationEntityConfig)
//   - RFC 9728 protected-resource metadata (protected_resource_metadata.go)
//   - the interactive consent challenge round-trip (logout_handler.go
//     issueConsentChallenge / consumeConsentChallenge / describeScopes /
//     scopesSubsumed)
//   - the /auth/send-code helper (logout_handler.go handleSendCode)
//   - OpenID Connect Native SSO 1.0 device_secret issuance + exchange
//     (handle_native_sso.go).
//
// REUSES rcovNewServer / rcovDirectLogin / rcovPostJSON / rcovDo from
// rootcov_flow_test.go. New helpers carry the rcov2 prefix.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/federation"
)

// TestRcov2Ext_DeviceFlowApproveAndPoll drives the full RFC 8628 device flow:
// start -> approve via /device/verify (bearer-authenticated) -> poll /token with
// the device_code grant. This covers handleDeviceVerify + handleDeviceTokenGrant.
func TestRcov2Ext_DeviceFlowApproveAndPoll(t *testing.T) {
	s := rcovNewServer(t, sso.WithDeviceCodeStore(
		defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, time.Nanosecond, rcov2DeviceVerifyURI))
	access, _ := rcovDirectLogin(t, s)

	// 1. Device starts the flow.
	status, out := rcovPostJSON(t, s.http.URL+"/device/code", "", map[string]any{
		"client_id": rcovClient,
		"scope":     "openid",
	})
	if status != http.StatusOK {
		t.Fatalf("device/code = %d body=%v", status, out)
	}
	deviceCode, _ := out["device_code"].(string)
	userCode, _ := out["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("missing device/user code: %v", out)
	}

	// 2. Before approval, polling returns authorization_pending.
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   deviceCode,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest || tok["error"] != "authorization_pending" {
		t.Fatalf("pending poll = %d %v, want 400 authorization_pending", status, tok)
	}

	// 3. The user approves via the verification endpoint (needs a valid bearer).
	status, out = rcovPostJSON(t, s.http.URL+"/device/verify", access, map[string]any{
		"user_code": userCode,
		"approve":   true,
	})
	if status != http.StatusOK {
		t.Fatalf("device/verify approve = %d body=%v", status, out)
	}

	// 4. The device polls again and now gets tokens (Interval is ~0 so no
	//    slow_down throttle between polls).
	status, tok = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   deviceCode,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("approved poll = %d body=%v, want 200", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("approved device poll has no access_token: %v", tok)
	}
}

const rcov2DeviceVerifyURI = "https://opt.example.com/device"

// TestRcov2Ext_DeviceVerifyDeny covers the denial branch of handleDeviceVerify
// (approve=false) plus the access_denied poll result.
func TestRcov2Ext_DeviceVerifyDeny(t *testing.T) {
	s := rcovNewServer(t, sso.WithDeviceCodeStore(
		defaultimpl.NewMemoryDeviceCodeStore(), 5*time.Minute, time.Nanosecond, rcov2DeviceVerifyURI))
	access, _ := rcovDirectLogin(t, s)

	_, out := rcovPostJSON(t, s.http.URL+"/device/code", "", map[string]any{
		"client_id": rcovClient,
		"scope":     "openid",
	})
	deviceCode, _ := out["device_code"].(string)
	userCode, _ := out["user_code"].(string)

	// Deny.
	status, _ := rcovPostJSON(t, s.http.URL+"/device/verify", access, map[string]any{
		"user_code": userCode,
		"approve":   false,
	})
	if status != http.StatusOK {
		t.Fatalf("device/verify deny = %d", status)
	}

	// Poll => access_denied.
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":    "urn:ietf:params:oauth:grant-type:device_code",
		"device_code":   deviceCode,
		"client_id":     rcovClient,
		"client_secret": rcovSecret,
	})
	if status != http.StatusBadRequest || tok["error"] != "access_denied" {
		t.Errorf("denied poll = %d %v, want 400 access_denied", status, tok)
	}

	// Verify with a missing bearer => 401.
	status, _ = rcovPostJSON(t, s.http.URL+"/device/verify", "", map[string]any{
		"user_code": userCode,
		"approve":   true,
	})
	if status != http.StatusUnauthorized {
		t.Errorf("device/verify no bearer = %d, want 401", status)
	}

	// Verify with an unknown user_code => 400 invalid_grant.
	status, _ = rcovPostJSON(t, s.http.URL+"/device/verify", access, map[string]any{
		"user_code": "ZZZZ-ZZZZ",
		"approve":   true,
	})
	if status != http.StatusBadRequest {
		t.Errorf("device/verify unknown code = %d, want 400", status)
	}
}

// TestRcov2Ext_HomeRealm covers B2B home-realm discovery: a known email domain
// resolves to its connection; an unknown one returns {"found": false}.
func TestRcov2Ext_HomeRealm(t *testing.T) {
	store := connections.NewMemoryStore()
	_ = store.Upsert(context.Background(), &connections.Connection{
		ID:          "acme-oidc",
		TenantID:    "acme",
		Type:        connections.TypeOIDC,
		DisplayName: "Acme SSO",
		Domains:     []string{"acme.com"},
		Enabled:     true,
	})
	s := rcovNewServer(t, sso.WithConnectionStore(store))

	// Known domain (GET with login_hint) => found.
	status, out := rcovDo(t, http.MethodGet,
		s.http.URL+"/auth/home-realm?login_hint=jane@acme.com", "", nil)
	if status != http.StatusOK {
		t.Fatalf("home-realm = %d body=%v", status, out)
	}
	if out["found"] != true || out["connection_id"] != "acme-oidc" {
		t.Errorf("home-realm found = %v, want acme-oidc: %v", out["found"], out)
	}
	if out["tenant_id"] != "acme" {
		t.Errorf("home-realm tenant = %v, want acme", out["tenant_id"])
	}

	// Unknown domain (POST with JSON body) => not found, not an error.
	status, out = rcovPostJSON(t, s.http.URL+"/auth/home-realm", "", map[string]any{
		"login_hint": "bob@unknown.example",
	})
	if status != http.StatusOK || out["found"] != false {
		t.Errorf("home-realm miss = %d %v, want 200 found:false", status, out)
	}
}

// TestRcov2Ext_FederationEntityConfig covers the OpenID Federation 1.0 entity
// configuration endpoint (handleFederationEntityConfig + BuildOPMetadata): the
// route is mounted by WithFederationEntity and serves a signed entity statement.
func TestRcov2Ext_FederationEntityConfig(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://fed.example.com"))
	s := rcovNewServer(t,
		sso.WithIssuer("https://fed.example.com"),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithFederationEntity(rcov2FederationConfig(), iss),
	)

	resp, err := http.Get(s.http.URL + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("federation entity config: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entity config status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/entity-statement+jwt" {
		t.Errorf("Content-Type = %q, want application/entity-statement+jwt", ct)
	}
	// It is public metadata (cacheable), not a credential.
	if cc := resp.Header.Get("Cache-Control"); cc == "" {
		t.Errorf("expected a Cache-Control header on the public entity statement")
	}
}

// TestRcov2Ext_ProtectedResourceMetadata covers the RFC 9728 endpoint
// (handleProtectedResourceMetadata + WithProtectedResourceMetadata).
func TestRcov2Ext_ProtectedResourceMetadata(t *testing.T) {
	s := rcovNewServer(t, sso.WithProtectedResourceMetadata(sso.ProtectedResourceMetadata{
		ResourceName:          "Coverage Resource",
		ResourceDocumentation: "https://docs.example.com",
	}))

	var doc map[string]any
	resp := rcovGetJSON(t, s.http.URL+"/.well-known/oauth-protected-resource", &doc)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("protected-resource metadata = %d, want 200", resp.StatusCode)
	}
	if doc["resource"] == "" || doc["resource"] == nil {
		t.Errorf("missing resource identifier: %v", doc)
	}
	if doc["resource_name"] != "Coverage Resource" {
		t.Errorf("resource_name = %v, want override", doc["resource_name"])
	}
	if _, ok := doc["jwks_uri"]; !ok {
		t.Errorf("missing jwks_uri: %v", doc)
	}
}

// TestRcov2Ext_ConsentChallenge covers the interactive consent gate: a
// non-SkipConsent client triggers consent_required + a challenge, which is then
// echoed back to complete the login (issueConsentChallenge / consumeConsentChallenge
// / describeScopes / scopesSubsumed).
func TestRcov2Ext_ConsentChallenge(t *testing.T) {
	s := rcov2ConsentServer(t)

	// First login: no prior grant => consent_required + a challenge.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcov2ConsentClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "profile"},
	})
	if status != http.StatusOK {
		t.Fatalf("consent-gate login = %d body=%v", status, out)
	}
	if out["error"] != "consent_required" {
		t.Fatalf("expected consent_required, got %v", out)
	}
	challenge, _ := out["consent_challenge_id"].(string)
	if challenge == "" {
		t.Fatalf("no consent_challenge_id returned: %v", out)
	}
	// Presentational enrichment is included.
	if _, ok := out["scopes"]; !ok {
		t.Errorf("consent response missing scopes description: %v", out)
	}

	// Second login echoing the challenge for the SAME scopes => mint.
	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":             "password",
		"client_id":            rcov2ConsentClient,
		"credential":           map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":                []string{"openid", "profile"},
		"consent_challenge_id": challenge,
	})
	if status != http.StatusOK {
		t.Fatalf("consent-approved login = %d body=%v", status, out)
	}
	if out["access_token"] == "" || out["access_token"] == nil {
		t.Errorf("consent-approved login minted no token: %v", out)
	}

	// A subsequent login for the same (now-granted, subsumed) scopes mints
	// without a fresh challenge (scopesSubsumed true path).
	status, out = rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcov2ConsentClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusOK || out["access_token"] == nil {
		t.Errorf("re-login on subsumed scopes = %d %v, want minted token", status, out)
	}
}

const rcov2ConsentClient = "rcov2-consent-client"

// rcov2ConsentServer builds a server whose client does NOT skip consent so the
// interactive consent gate fires.
func rcov2ConsentServer(t *testing.T) *rcovServer {
	t.Helper()
	s := rcovNewServer(t)
	// Seed a second client that requires consent (rcovClient has SkipConsent).
	s.clients.AddSeed(&sso.Client{
		ID:                    rcov2ConsentClient,
		Secret:                rcovSecret,
		Name:                  "Consent Client",
		RedirectURIs:          []string{rcovRedirect},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
		SkipConsent:           false,
	})
	return s
}

// TestRcov2Ext_SendCode covers /auth/send-code error branches (handleSendCode):
// missing fields, an unsupported provider, and a provider that cannot send
// codes. The success path needs a CodeSender authenticator wired.
func TestRcov2Ext_SendCode(t *testing.T) {
	s := rcovNewServer(t)

	// Missing provider/target => 400.
	status, _ := rcovPostJSON(t, s.http.URL+"/auth/send-code", "", map[string]any{})
	if status != http.StatusBadRequest {
		t.Errorf("send-code empty = %d, want 400", status)
	}

	// Unknown provider => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/auth/send-code", "", map[string]any{
		"provider": "no-such-provider",
		"target":   "+15551234567",
	})
	if status != http.StatusBadRequest {
		t.Errorf("send-code unknown provider = %d, want 400", status)
	}

	// The wired "password" authenticator is not a CodeSender => 400.
	status, _ = rcovPostJSON(t, s.http.URL+"/auth/send-code", "", map[string]any{
		"provider": "password",
		"target":   "alice",
	})
	if status != http.StatusBadRequest {
		t.Errorf("send-code non-sender provider = %d, want 400", status)
	}
}

// TestRcov2Ext_SendCodeSuccess covers the SUCCESS path of handleSendCode with a
// real CodeSender authenticator wired (recordCodeSent success leg). The
// PhoneAuthenticator implements spi.CodeSender via SendCode.
func TestRcov2Ext_SendCodeSuccess(t *testing.T) {
	var delivered bool
	sender := authenticators.SMSSenderFunc(func(_ context.Context, _, _ string) error {
		delivered = true
		return nil
	})
	phone := authenticators.NewPhoneAuthenticator(authenticators.NewMemoryCodeStore(), sender)
	s := rcovNewServer(t, sso.WithAuthenticator(phone))

	status, out := rcovPostJSON(t, s.http.URL+"/auth/send-code", "", map[string]any{
		"provider": phone.Name(),
		"target":   "+15551234567",
	})
	if status != http.StatusOK {
		t.Fatalf("send-code success = %d body=%v", status, out)
	}
	if !delivered {
		t.Errorf("the code sender was never invoked")
	}
}

// TestRcov2Ext_NativeSSO covers OpenID Connect Native SSO 1.0: a login with the
// device_sso scope mints a device_secret + ds_hash-bound id_token, which a
// second app exchanges (subject_token=id_token, actor_token=device_secret) for
// its own tokens. Drives issueDeviceSecret + handleDeviceSecretExchange + the
// ds_hash helpers (dsHash / idTokenAlg / idTokenDsHash / jwsSegment).
func TestRcov2Ext_NativeSSO(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	s := rcovNewServer(t,
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDeviceSecretStore(defaultimpl.NewMemoryDeviceSecretStore(), time.Minute),
	)

	// First app logs in requesting device_sso + openid => gets id_token + device_secret.
	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid", "device_sso"},
	})
	if status != http.StatusOK {
		t.Fatalf("native-sso login = %d body=%v", status, out)
	}
	idToken, _ := out["id_token"].(string)
	deviceSecret, _ := out["device_secret"].(string)
	if idToken == "" || deviceSecret == "" {
		t.Fatalf("native-sso login missing id_token/device_secret: %v", out)
	}

	// Second app exchanges the id_token + device_secret for its own tokens.
	status, tok := rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      idToken,
		"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
		"actor_token":        deviceSecret,
		"actor_token_type":   "urn:openid:params:token-type:device-secret",
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusOK {
		t.Fatalf("native-sso exchange = %d body=%v, want 200", status, tok)
	}
	if tok["access_token"] == "" || tok["access_token"] == nil {
		t.Errorf("native-sso exchange minted no access_token: %v", tok)
	}

	// Replaying the now-consumed device_secret collapses to invalid_grant
	// (oracle-safe single-use).
	status, tok = rcovPostJSON(t, s.http.URL+"/token", "", map[string]any{
		"grant_type":         "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":      idToken,
		"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
		"actor_token":        deviceSecret,
		"actor_token_type":   "urn:openid:params:token-type:device-secret",
		"client_id":          rcovClient,
		"client_secret":      rcovSecret,
	})
	if status != http.StatusBadRequest || tok["error"] != "invalid_grant" {
		t.Errorf("native-sso replay = %d %v, want 400 invalid_grant", status, tok)
	}
}

// rcov2FederationConfig is a minimal slice-1 (leaf entity, no subordinates,
// no trust anchors) federation config — enough to mount + serve the entity
// configuration endpoint.
func rcov2FederationConfig() *federation.Config {
	return &federation.Config{
		AuthorityHints:     []string{"https://federation.example.com/anchor"},
		OrganizationName:   "Coverage Org",
		Contacts:           []string{"mailto:ops@coverage.example.com"},
		EntityStatementTTL: 6 * time.Hour,
	}
}
