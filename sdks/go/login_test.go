package snaplink

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestLoginRedirectAndCallback(t *testing.T) {
	var tokenForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		tokenForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access-1", ExpiresIn: 900, TokenType: "Bearer"})
	}))
	defer server.Close()

	client := NewClient(nil, server.Client())
	options := LoginOptions{
		BaseURL: server.URL, ClientID: "spa-client",
		RedirectURI: server.URL + "/auth/callback", ReturnTo: server.URL + "/dashboard",
	}
	started, err := client.Login(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	loginURL, err := url.Parse(started.RedirectURL)
	if err != nil {
		t.Fatal(err)
	}
	if loginURL.Path != "/login/" || loginURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("unexpected login URL: %s", started.RedirectURL)
	}
	callback := options
	callback.CallbackURL = options.RedirectURI + "?code=code-1&state=" + url.QueryEscape(loginURL.Query().Get("state")) + "&iss=" + url.QueryEscape(server.URL)
	completed, err := client.Login(context.Background(), callback)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Tokens == nil || completed.Tokens.AccessToken != "access-1" {
		t.Fatalf("unexpected token result: %#v", completed)
	}
	if tokenForm.Get("grant_type") != "authorization_code" || tokenForm.Get("client_secret") != "" {
		t.Fatalf("unexpected token form: %v", tokenForm)
	}
	if len(tokenForm.Get("code_verifier")) < 43 {
		t.Fatalf("missing PKCE verifier: %v", tokenForm)
	}
}

func TestLoginRejectsStateMismatch(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client := NewClient(nil, server.Client())
	options := LoginOptions{BaseURL: server.URL, ClientID: "spa-client", RedirectURI: server.URL + "/callback"}
	started, err := client.Login(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	loginURL, _ := url.Parse(started.RedirectURL)
	options.CallbackURL = options.RedirectURI + "?code=code&state=wrong&iss=" + url.QueryEscape(server.URL)
	_, err = client.Login(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "state did not match") {
		t.Fatalf("expected state mismatch, got %v", err)
	}
	if loginURL.Query().Get("state") == "wrong" {
		t.Fatal("test state was not distinct")
	}
}

func TestSetupClaimsActivationAfterLogin(t *testing.T) {
	var prepareBody map[string]any
	var claimAuthorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/activation/prepare":
			if err := json.NewDecoder(r.Body).Decode(&prepareBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(ActivationPreparation{ActivationTicket: "ticket-1", ExpiresIn: 300, ProductID: "pro"})
		case "/token":
			_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access-setup", ExpiresIn: 900, TokenType: "Bearer"})
		case "/api/v1/me/activation/claim":
			claimAuthorization = r.Header.Get("Authorization")
			_ = json.NewEncoder(w).Encode(map[string]any{"context": map[string]any{"product_id": "pro", "tenant_id": "tenant-1"}})
		case "/api/v1/me/account-context":
			_ = json.NewEncoder(w).Encode(map[string]any{"context": map[string]any{"product_id": "pro", "tenant_id": "tenant-1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(nil, server.Client())
	_, err := client.Setup(context.Background(), SetupOptions{
		BaseURL: server.URL, ClientID: "spa-client", ProductID: "pro", LicenseKey: "paid-secret",
		AllowInsecureHTTPForDevelopment: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	options := LoginOptions{
		BaseURL: server.URL, ClientID: "spa-client", RedirectURI: server.URL + "/callback",
		AllowInsecureHTTPForDevelopment: true,
	}
	started, err := client.Login(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	loginURL, _ := url.Parse(started.RedirectURL)
	if strings.Contains(started.RedirectURL, "paid-secret") {
		t.Fatal("activation credential leaked into redirect URL")
	}
	callback := options
	callback.CallbackURL = options.RedirectURI + "?code=code-setup&state=" + url.QueryEscape(loginURL.Query().Get("state")) + "&iss=" + url.QueryEscape(server.URL)
	completed, err := client.Login(context.Background(), callback)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Tokens == nil || completed.Tokens.AccessToken != "access-setup" {
		t.Fatalf("unexpected token result: %#v", completed)
	}
	if prepareBody["license_key"] != "paid-secret" || prepareBody["client_id"] != "spa-client" {
		t.Fatalf("unexpected setup body: %#v", prepareBody)
	}
	if claimAuthorization != "Bearer access-setup" {
		t.Fatalf("activation claim was not bearer-authenticated: %q", claimAuthorization)
	}
	account, err := client.GetAccountContext(context.Background(), "pro")
	if err != nil || account.TenantID != "tenant-1" {
		t.Fatalf("unexpected account context: %#v, %v", account, err)
	}
}
