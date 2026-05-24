package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	terarUserID   = "u-terar"
	terarClientID = "terar-client"
	terarSecret   = "terar-secret"
	terarPassword = "pw"
)

func newTokenExchangeRARHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: terarUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: terarClientID, Secret: terarSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != terarPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: terarUserID, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestTokenExchange_PreservesAuthorizationDetails(t *testing.T) {
	srv := newTokenExchangeRARHarness(t)
	const details = `[{"type":"payment_initiation","amount":"42","currency":"EUR"}]`

	// Mint a token carrying authorization_details.
	body, _ := json.Marshal(map[string]any{
		"provider":              "password",
		"client_id":             terarClientID,
		"credential":            map[string]string{"username": terarUserID, "password": terarPassword},
		"authorization_details": json.RawMessage(details),
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var loginOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&loginOut)
	subjectToken, _ := loginOut["access_token"].(string)
	if subjectToken == "" {
		t.Fatalf("no access_token from login")
	}

	// Confirm RAR is on the original token (sanity).
	origPayload := decodeAccessTokenPayload(t, subjectToken)
	if _, ok := origPayload["authorization_details"]; !ok {
		t.Fatalf("RAR missing on original token: %v", origPayload)
	}

	// Exchange it.
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {terarClientID},
		"client_secret":      {terarSecret},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	exResp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer exResp.Body.Close()
	rb, _ := io.ReadAll(exResp.Body)
	if exResp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", exResp.StatusCode, rb)
	}
	var exOut map[string]any
	_ = json.Unmarshal(rb, &exOut)
	exchanged, _ := exOut["access_token"].(string)
	exPayload := decodeAccessTokenPayload(t, exchanged)
	ad, ok := exPayload["authorization_details"].([]any)
	if !ok {
		t.Fatalf("RAR LOST on token-exchange: %v", exPayload)
	}
	if len(ad) != 1 {
		t.Errorf("RAR has wrong length on exchanged token: %v", ad)
	}
	elem, _ := ad[0].(map[string]any)
	if elem["type"] != "payment_initiation" || elem["amount"] != "42" {
		t.Errorf("RAR fields lost on exchange: %v", elem)
	}
}

func TestTokenExchange_NoAuthorizationDetailsStaysClean(t *testing.T) {
	// Sanity: a subject_token WITHOUT RAR doesn't conjure one on
	// the exchanged token. Confirms the propagation only fires
	// when the subject_token had a binding.
	srv := newTokenExchangeRARHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  terarClientID,
		"credential": map[string]string{"username": terarUserID, "password": terarPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var loginOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&loginOut)
	subjectToken, _ := loginOut["access_token"].(string)

	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {terarClientID},
		"client_secret":      {terarSecret},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	}
	exResp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer exResp.Body.Close()
	rb, _ := io.ReadAll(exResp.Body)
	var exOut map[string]any
	_ = json.Unmarshal(rb, &exOut)
	exchanged, _ := exOut["access_token"].(string)
	exPayload := decodeAccessTokenPayload(t, exchanged)
	if _, present := exPayload["authorization_details"]; present {
		t.Errorf("RAR fabricated on token without original binding: %v", exPayload["authorization_details"])
	}
}
