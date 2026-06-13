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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// RFC 9207 Authorization Server Issuer Identification — every
// authorization response (success + error) carries `iss`, and the
// discovery doc advertises support.

func TestRFC9207_DiscoveryAdvertisesSupport(t *testing.T) {
	srv := newDiscoveryServer(t, true)
	doc := fetchDiscovery(t, srv)
	got, ok := doc["authorization_response_iss_parameter_supported"].(bool)
	if !ok {
		t.Fatalf("authorization_response_iss_parameter_supported missing or non-bool: %v", doc["authorization_response_iss_parameter_supported"])
	}
	if !got {
		t.Errorf("authorization_response_iss_parameter_supported = false, want true (server always stamps iss)")
	}
}

func TestRFC9207_CodeFlowResponseCarriesIss(t *testing.T) {
	httpSrv, _, _ := newCodeFlowServer(t)

	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": codeUsername, "password": codePassword},
		"response_type": "code",
		"redirect_uri":  codeRedirectURI,
		"state":         "xyz",
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	gotIss, _ := out["iss"].(string)
	if gotIss == "" {
		t.Fatalf("iss missing from success code response: %s", raw)
	}
	// Server has no WithIssuer set, so iss falls back to the request
	// base URL — must match the httptest URL the client just dialed.
	if gotIss != httpSrv.URL {
		t.Errorf("iss = %q want %q (request base URL)", gotIss, httpSrv.URL)
	}
}

func TestRFC9207_DirectMintResponseCarriesIss(t *testing.T) {
	httpSrv := newDirectMintServer(t)

	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  issDirectClient,
		"credential": map[string]string{"username": issDirectUser, "password": issDirectPass},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["access_token"] == "" || out["access_token"] == nil {
		t.Fatalf("expected an access_token in direct-mint response: %s", raw)
	}
	if out["iss"] != httpSrv.URL {
		t.Errorf("iss = %v want %q (request base URL)", out["iss"], httpSrv.URL)
	}
}

func TestRFC9207_ErrorResponseCarriesIss(t *testing.T) {
	httpSrv, _, _ := newCodeFlowServer(t)

	// Trigger ErrInvalidRedirectURI: redirect_uri not in client allowlist.
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     codeClient,
		"credential":    map[string]string{"username": codeUsername, "password": codePassword},
		"response_type": "code",
		"redirect_uri":  "https://attacker.example/steal",
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s want 400", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %v want invalid_redirect_uri", out["error"])
	}
	// RFC 9207 §2: error responses MUST include iss so a client can
	// still detect a mix-up even on the error path.
	if out["iss"] != httpSrv.URL {
		t.Errorf("iss missing or wrong on error response: got %v want %q", out["iss"], httpSrv.URL)
	}
}

func TestRFC9207_IssMatchesConfiguredIssuer(t *testing.T) {
	// When WithIssuer is set explicitly, iss in authorization responses
	// MUST equal that value (matches discovery's `issuer` field) so
	// clients comparing iss against discovery succeed.
	const wantIssuer = "https://sso.example.com"

	httpSrv := newDirectMintServerWith(t, sso.WithIssuer(wantIssuer))

	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  issDirectClient,
		"credential": map[string]string{"username": issDirectUser, "password": issDirectPass},
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["iss"] != wantIssuer {
		t.Errorf("iss = %v want %q (matches WithIssuer)", out["iss"], wantIssuer)
	}
}

func TestRFC9207_DiscoveryIssAndResponseIssAgree(t *testing.T) {
	// Cross-check: the iss in an authorization response and the issuer
	// in the discovery document MUST be the same string. This is the
	// invariant that makes RFC 9207 mix-up defense work — the client
	// already pinned to a discovery issuer, and the response carries
	// the same value.
	httpSrv := newDirectMintServer(t)

	// Fetch discovery.
	dresp, err := http.Get(httpSrv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	draw, _ := io.ReadAll(dresp.Body)
	_ = dresp.Body.Close()
	var disco map[string]any
	_ = json.Unmarshal(draw, &disco)
	discoIss, _ := disco["issuer"].(string)
	if discoIss == "" {
		t.Fatalf("discovery doc missing issuer: %s", draw)
	}

	// Drive a successful login.
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  issDirectClient,
		"credential": map[string]string{"username": issDirectUser, "password": issDirectPass},
	})
	lresp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	lraw, _ := io.ReadAll(lresp.Body)
	_ = lresp.Body.Close()
	var login map[string]any
	_ = json.Unmarshal(lraw, &login)

	loginIss, _ := login["iss"].(string)
	if loginIss != discoIss {
		t.Errorf("iss mismatch: discovery %q vs authorization response %q — RFC 9207 §2 invariant broken", discoIss, loginIss)
	}
}

func TestRFC9207_ProviderListResponseCarriesIss(t *testing.T) {
	// The "list providers" branch (empty provider field) is the
	// pre-authentication discovery probe an SPA fires to render a
	// provider chooser. RFC 9207 still wants iss there so the client
	// can pin the AS identity before showing the chooser.
	httpSrv, _, _ := newCodeFlowServer(t)

	body, _ := json.Marshal(map[string]any{
		"client_id": codeClient,
	})
	resp, err := http.Post(httpSrv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if _, ok := out["providers"].([]any); !ok {
		t.Errorf("providers field missing or wrong type: %v", out)
	}
	if out["iss"] != httpSrv.URL {
		t.Errorf("iss missing on provider-list response: %v", out["iss"])
	}
}

// ---- harness ----

const (
	issDirectClient = "iss-direct-client"
	issDirectUser   = "u-iss-bob"
	issDirectPass   = "pw"
)

func newDirectMintServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newDirectMintServerWith(t)
}

// newDirectMintServerWith stands up a minimal server for the direct-mint
// /auth/login path (no response_type=code). Extra options layer on top.
func newDirectMintServerWith(t *testing.T, extra ...sso.Option) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: issDirectUser})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    issDirectClient,
		Secret:                "secret",
		Name:                  "Direct Mint",
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == issDirectUser && p == issDirectPass {
				return &sso.AuthResult{UserID: issDirectUser}, nil
			}
			return nil, errors.New("bad")
		},
	))

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	opts = append(opts, extra...)

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}
