package remote_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/ssoclient"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
)

var _ ssoclient.TokenClient = (*remote.TokenClient)(nil)

func TestTokenClientGeneratePKCE(t *testing.T) {
	client := remote.NewTokenClient("https://sso.example/token", remote.WithClientID("app"))
	verifier, challenge, err := client.GeneratePKCE()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(verifier))
	if len(verifier) < 43 || challenge != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("invalid PKCE pair verifier=%q challenge=%q", verifier, challenge)
	}
}

func TestTokenClientAuthorizationCodeURL(t *testing.T) {
	client := remote.NewTokenClient("https://sso.example/token",
		remote.WithAuthorizationEndpoint("https://sso.example/auth/login?prompt=login"),
		remote.WithClientID("app"), remote.WithRedirectURI("https://app.example/callback"))
	target, verifier, err := client.AuthorizationCodeURL("state-1", "openid", "profile")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	sum := sha256.Sum256([]byte(verifier))
	if query.Get("client_id") != "app" || query.Get("state") != "state-1" {
		t.Fatalf("authorization query = %#v", query)
	}
	if query.Get("scope") != "openid profile" || query.Get("prompt") != "login" {
		t.Fatalf("authorization options = %#v", query)
	}
	if query.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) ||
		query.Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE query = %#v", query)
	}
}

func TestTokenClientExchangeCode(t *testing.T) {
	var received url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Pragma") != "no-cache" {
			t.Error("credential request omitted no-store headers")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		received = r.Form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access", "refresh_token": "refresh", "expires_in": 300,
			"scope": "openid profile", "token_type": "Bearer", "id_token": "id",
		})
	}))
	defer server.Close()
	client := remote.NewTokenClient(server.URL,
		remote.WithClientID("app"), remote.WithRedirectURI("https://app.example/callback"))
	verifier, _, _ := client.GeneratePKCE()
	token, err := client.ExchangeCode(context.Background(), "code", verifier)
	if err != nil {
		t.Fatal(err)
	}
	if received.Get("grant_type") != "authorization_code" || received.Get("client_id") != "app" {
		t.Fatalf("form = %#v", received)
	}
	if received.Get("code_verifier") != verifier || received.Get("redirect_uri") == "" {
		t.Fatalf("PKCE form = %#v", received)
	}
	if token.AccessToken != "access" || token.IDToken != "id" || len(token.Scopes) != 2 {
		t.Fatalf("token = %#v", token)
	}
}

func TestTokenClientMapsOAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()
	client := remote.NewTokenClient(server.URL, remote.WithClientID("app"))
	verifier, _, _ := client.GeneratePKCE()
	_, err := client.ExchangeCode(context.Background(), "code", verifier)
	if !errors.Is(err, ssoclient.ErrInvalidGrant) {
		t.Fatalf("error = %v, want ErrInvalidGrant", err)
	}
}

func TestTokenClientRejectsMissingAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"token_type":"Bearer"}`))
	}))
	defer server.Close()
	client := remote.NewTokenClient(server.URL, remote.WithClientID("app"))
	verifier, _, _ := client.GeneratePKCE()
	if _, err := client.ExchangeCode(context.Background(), "code", verifier); err == nil {
		t.Fatal("2xx without access_token must fail closed")
	}
}

func TestTokenClientBasicCredentialsWin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "basic" || password != "secret" {
			t.Fatalf("basic auth = %q/%q/%v", user, password, ok)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("client_id") != "basic" || r.Form.Get("client_secret") != "" {
			t.Fatalf("form credentials = %#v", r.Form)
		}
		_, _ = w.Write([]byte(`{"access_token":"access"}`))
	}))
	defer server.Close()
	client := remote.NewTokenClient(server.URL,
		remote.WithFormClientCredentials("form", "form-secret"),
		remote.WithClientCredentials("basic", "secret"))
	if _, err := client.ClientCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
}
