package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	sidUserID   = "u-sid"
	sidClientID = "sid-client"
	sidSecret   = "sid-secret"
	sidPassword = "pw"
)

// newSIDHarness wires a server that has every ingredient needed to
// observe the sid claim end-to-end: SessionManager (the sid source),
// Ed25519 issuer shared between access + id tokens, refresh token
// store (to drive rotation), and a no-op password authenticator.
func newSIDHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: sidUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: sidClientID, Secret: sidSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != sidPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: sidUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(2 * time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(defaultimpl.NewMemoryRefreshTokenStore(), 30*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginSID(t *testing.T, srv *httptest.Server, scope []string) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  sidClientID,
		"credential": map[string]string{"username": sidUserID, "password": sidPassword},
		"scope":      scope,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("login status=%d body=%s", resp.StatusCode, body)
	}
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func TestSID_StampedOnAccessTokenAfterLogin(t *testing.T) {
	srv := newSIDHarness(t)
	body := loginSID(t, srv, []string{"openid"})
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token in login response: %v", body)
	}
	payload := decodeAccessTokenPayload(t, access)
	sid, _ := payload["sid"].(string)
	if sid == "" {
		t.Fatalf("access token missing sid claim: %v", payload)
	}
	// And it must equal the session_id surfaced in the login
	// response — the contract is "sid == active session id" so
	// RPs that cache session_id at first login can match it on
	// later logout_tokens.
	if sessID, _ := body["session_id"].(string); sessID != sid {
		t.Errorf("sid claim (%q) != response session_id (%q)", sid, sessID)
	}
}

func TestSID_StampedOnIDTokenAfterLogin(t *testing.T) {
	srv := newSIDHarness(t)
	body := loginSID(t, srv, []string{"openid"})
	idTok, _ := body["id_token"].(string)
	if idTok == "" {
		t.Fatalf("no id_token in login response (openid scope set): %v", body)
	}
	payload := decodeAccessTokenPayload(t, idTok)
	if sid, _ := payload["sid"].(string); sid == "" {
		t.Fatalf("id_token missing sid claim: %v", payload)
	}
}

func TestSID_StableAcrossRefreshRotation(t *testing.T) {
	srv := newSIDHarness(t)
	body := loginSID(t, srv, []string{"openid"})
	originalAccess, _ := body["access_token"].(string)
	originalSID, _ := decodeAccessTokenPayload(t, originalAccess)["sid"].(string)
	if originalSID == "" {
		t.Fatalf("no sid on original token; precondition failed")
	}
	refresh, _ := body["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token; refresh store wiring expected")
	}

	form := "grant_type=refresh_token&refresh_token=" + refresh +
		"&client_id=" + sidClientID + "&client_secret=" + sidSecret
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	newAccess, _ := out["access_token"].(string)
	newSID, _ := decodeAccessTokenPayload(t, newAccess)["sid"].(string)
	if newSID != originalSID {
		t.Errorf("sid changed across rotation: original=%q new=%q (expected stable)", originalSID, newSID)
	}
}

func TestSID_DiscoveryFlagsFlipWhenSessionManagerWired(t *testing.T) {
	srv := newSIDHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	// BCL flag flips only when LogoutTokenIssuer + LogoutNotifier
	// are wired — this harness omits them, so backchannel_logout_*
	// flags both stay absent / false. The harness DOES wire a
	// SessionManager, but the base condition for the session
	// flag is the parent flag. So both null. That is the design
	// — session support is a refinement of base support.
	if _, present := doc["backchannel_logout_session_supported"]; present {
		t.Errorf("backchannel_logout_session_supported leaked without base support: %v", doc["backchannel_logout_session_supported"])
	}
}

func TestSID_ClientCredentialsTokenHasNoSID(t *testing.T) {
	// client_credentials has no end-user session → token MUST
	// NOT carry a sid claim. Confirms the issuer only stamps
	// when Subject.SID is populated.
	srv := newSIDHarness(t)
	form := "grant_type=client_credentials&client_id=" + sidClientID + "&client_secret=" + sidSecret
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatalf("cc: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cc status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	payload := decodeAccessTokenPayload(t, access)
	if sid, _ := payload["sid"].(string); sid != "" {
		t.Errorf("client_credentials token unexpectedly carries sid=%q", sid)
	}
}
