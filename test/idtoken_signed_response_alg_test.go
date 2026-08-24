package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
)

// TestIDTokenSignedResponseAlg_EndToEnd is the FAPI-unblock proof end to
// end: one server signs a DCR-registered RS256 client's ID tokens with RS256
// (the OIDF suite's hard-coded login decoder) while plain clients keep the
// default EdDSA issuer, discovery advertises the union, and an unwired alg
// is rejected at registration with 400 invalid_client_metadata.
func TestIDTokenSignedResponseAlg_EndToEnd(t *testing.T) {
	const user, clientSec, pw = "u-rp", "s3cr3t", "pw"
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: user, Name: "R"})
	clients := defaultimpl.NewMemoryClientStore()
	pwAuth := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != pw {
				return nil, errPW
			}
			return &sso.AuthResult{UserID: user, Provider: "password"}, nil
		},
	))
	edIss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	rsaIss := defaultimpl.NewRSAJWTIssuer(
		defaultimpl.WithRSAIssuer("rs256-login"),
		defaultimpl.WithRSAAlg("RS256"),
		defaultimpl.WithRSATokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pwAuth),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", edIss),
		sso.WithTokenIssuer("jwt-rs256", rsaIss),
		sso.WithIDTokenIssuer(edIss),
		sso.WithIDTokenIssuerAlg("RS256", rsaIss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDynamicClientRegistration(oauth.DCRPolicy{
			AllowOpenRegistration: true,
			DefaultActive:         true,
			DefaultTokenStrategy:  "jwt",
		}),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// ---- discovery advertises the union of wired algs ----
	dr, err := http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	var disco map[string]any
	_ = json.NewDecoder(dr.Body).Decode(&disco)
	_ = dr.Body.Close()
	algsAny, _ := disco["id_token_signing_alg_values_supported"].([]any)
	algs := make([]string, 0, len(algsAny))
	for _, a := range algsAny {
		algs = append(algs, a.(string))
	}
	if !slices.Contains(algs, "EdDSA") || !slices.Contains(algs, "RS256") {
		t.Fatalf("id_token_signing_alg_values_supported = %v, want {EdDSA, RS256}", algs)
	}

	// ---- DCR: RS256 client registers; unwired alg rejected ----
	badStatus, badBody := postDCR(t, ts, "", map[string]any{
		"client_name":                  "bad",
		"redirect_uris":                []string{"https://rp.example/cb"},
		"id_token_signed_response_alg": "HS256",
	})
	if badStatus != http.StatusBadRequest || badBody["error"] != "invalid_client_metadata" {
		t.Fatalf("unwired alg: status=%d body=%v, want 400 invalid_client_metadata", badStatus, badBody)
	}

	rs256Status, rs256Body := postDCR(t, ts, "", map[string]any{
		"client_name":                  "fapi-login",
		"redirect_uris":                []string{"https://rp.example/cb"},
		"grant_types":                  []string{"authorization_code"},
		"id_token_signed_response_alg": "RS256",
	})
	if rs256Status != http.StatusCreated {
		t.Fatalf("RS256 register: status=%d body=%v", rs256Status, rs256Body)
	}
	if got, _ := rs256Body["id_token_signed_response_alg"].(string); got != "RS256" {
		t.Fatalf("register echo id_token_signed_response_alg = %q, want RS256", got)
	}
	rs256ID, _ := rs256Body["client_id"].(string)

	plainStatus, plainBody := postDCR(t, ts, "", map[string]any{
		"client_name":   "plain",
		"redirect_uris": []string{"https://rp.example/cb"},
		"grant_types":   []string{"authorization_code"},
	})
	if plainStatus != http.StatusCreated {
		t.Fatalf("plain register: status=%d body=%v", plainStatus, plainBody)
	}
	plainID, _ := plainBody["client_id"].(string)

	// ---- login: the per-alg client's id_token carries RS256; the default
	// client's carries EdDSA (byte-identical default path) ----
	gotAlg := loginIDTokenAlg(t, ts, rs256ID, clientSec)
	if gotAlg != "RS256" {
		t.Errorf("RS256 client id_token alg = %q, want RS256", gotAlg)
	}
	gotAlg = loginIDTokenAlg(t, ts, plainID, clientSec)
	if gotAlg != "EdDSA" {
		t.Errorf("plain client id_token alg = %q, want EdDSA (default issuer)", gotAlg)
	}
}

// loginIDTokenAlg performs a password login for the client and returns the
// JOSE `alg` header of the returned id_token.
func loginIDTokenAlg(t *testing.T, ts *httptest.Server, clientID, secret string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     clientID,
		"client_secret": secret,
		"credential":    map[string]string{"username": "u-rp", "password": "pw"},
		"scope":         []string{"openid"},
	})
	lr, err := http.Post(ts.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := io.ReadAll(lr.Body)
	_ = lr.Body.Close()
	var login map[string]any
	_ = json.Unmarshal(lb, &login)
	idt, _ := login["id_token"].(string)
	if idt == "" {
		t.Fatalf("no id_token in login response: %s", lb)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(strings.SplitN(idt, ".", 2)[0])
	if err != nil {
		t.Fatalf("id_token header decode: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("id_token header parse: %v", err)
	}
	return h.Alg
}
