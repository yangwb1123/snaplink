package sso_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
)

const (
	txacrUser   = "u-txacr"
	txacrClient = "txacr-client"
	txacrSecret = "txacr-secret"
	txacrAPI    = "https://api.example.com"
)

func newTxACRHarness(t *testing.T) (*httptest.Server, sso.TokenIssuer) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: txacrUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: txacrClient, Secret: txacrSecret, Active: true,
		TokenStrategy:    "jwt",
		AllowedResources: []string{txacrAPI},
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, issuer
}

func mintSubjectToken(t *testing.T, issuer sso.TokenIssuer, acr string) string {
	t.Helper()
	tok, err := issuer.Issue(context.Background(), &sso.Subject{
		ID:        txacrUser,
		ClientID:  txacrClient,
		ACR:       acr,
		AuthTime:  time.Now(),
		Resources: []string{txacrAPI},
	}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok.AccessToken
}

func txACRExchange(t *testing.T, srv *httptest.Server, subjectToken, acrDemand string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {txacrClient},
		"client_secret":      {txacrSecret},
		"subject_token":      {subjectToken},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"resource":           {txacrAPI},
	}
	if acrDemand != "" {
		form.Set("acr_values", acrDemand)
	}
	resp, err := http.PostForm(srv.URL+"/token", form)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	body := map[string]any{}
	_ = json.Unmarshal(raw, &body)
	return resp.StatusCode, body
}

func TestTokenExchange_ACRDemandSatisfied(t *testing.T) {
	srv, issuer := newTxACRHarness(t)
	subj := mintSubjectToken(t, issuer, "urn:mace:incommon:iap:silver")
	status, body := txACRExchange(t, srv, subj, "urn:mace:incommon:iap:silver")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200", status, body)
	}
}

func TestTokenExchange_ACRDemandUnsatisfiedReturnsInsufficient(t *testing.T) {
	srv, issuer := newTxACRHarness(t)
	subj := mintSubjectToken(t, issuer, "urn:mace:incommon:iap:silver")
	status, body := txACRExchange(t, srv, subj, "urn:mace:incommon:iap:gold")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 for ACR mismatch", status)
	}
	if body["error"] != security.ErrInsufficientUserAuthentication {
		t.Errorf("error=%v want %q", body["error"], security.ErrInsufficientUserAuthentication)
	}
}

func TestTokenExchange_ACREmptyInboundFailsAnyDemand(t *testing.T) {
	srv, issuer := newTxACRHarness(t)
	subj := mintSubjectToken(t, issuer, "") // no ACR on subject token
	status, body := txACRExchange(t, srv, subj, "urn:mace:incommon:iap:bronze")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", status)
	}
	if body["error"] != security.ErrInsufficientUserAuthentication {
		t.Errorf("error=%v want %q", body["error"], security.ErrInsufficientUserAuthentication)
	}
}

func TestTokenExchange_NoACRDemandLegacyBehavior(t *testing.T) {
	// Backward compat: when caller omits acr_values, exchange
	// succeeds regardless of inbound ACR.
	srv, issuer := newTxACRHarness(t)
	subj := mintSubjectToken(t, issuer, "")
	status, body := txACRExchange(t, srv, subj, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200", status, body)
	}
}

func TestTokenExchange_ACRDemandAcceptsAnyMatchingValue(t *testing.T) {
	// Space-separated demand: token's ACR matches any value → pass.
	srv, issuer := newTxACRHarness(t)
	subj := mintSubjectToken(t, issuer, "urn:mace:incommon:iap:silver")
	status, body := txACRExchange(t, srv, subj, "urn:mace:incommon:iap:gold urn:mace:incommon:iap:silver")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v want 200 (silver in demand set)", status, body)
	}
}
