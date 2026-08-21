package config

import (
	"strings"
	"testing"
)

func TestValidateConfiguredClientsLoginPageURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{name: "unset"},
		{name: "https", uri: "https://login.example.test/authorize"},
		{name: "loopback http", uri: "http://127.0.0.1:8081/login/"},
		{name: "public http", uri: "http://login.example.test/authorize", wantErr: true},
		{name: "userinfo", uri: "https://operator@login.example.test/authorize", wantErr: true},
		{name: "relative", uri: "/authorize", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfiguredClients(&Config{Clients: []ClientConfig{{ID: "portal", LoginPageURI: test.uri}}})
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "login_page_uri") {
					t.Fatalf("err=%v, want login_page_uri validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateConfiguredClients() error = %v", err)
			}
		})
	}
}

// TestValidateConfiguredClients_IDTokenSignedResponseAlg covers the static-
// config gate for clients[].id_token_signed_response_alg: the value must
// equal the JWS algorithm the wired signing issuer produces
// (canonicalSigningAlg(keys.signing.alg)); any other value — including
// "none" — fails config validation at boot, mirroring the DCR rule.
func TestValidateConfiguredClients_IDTokenSignedResponseAlg(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		signAlg string // keys.signing.alg
		client  ClientConfig
		wantErr bool
	}{
		{name: "empty alg always ok", signAlg: "", client: ClientConfig{ID: "a"}, wantErr: false},
		{name: "matches default eddsa", signAlg: "", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "EdDSA"}, wantErr: false},
		{name: "matches eddsa alias", signAlg: "eddsa", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "EdDSA"}, wantErr: false},
		{name: "matches es256", signAlg: "es256", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "ES256"}, wantErr: false},
		{name: "matches rs256", signAlg: "rs256", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "RS256"}, wantErr: false},
		{name: "matches ps256", signAlg: "ps256", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "PS256"}, wantErr: false},
		{name: "unwired alg rejected", signAlg: "es256", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "RS256"}, wantErr: true},
		{name: "alg none rejected", signAlg: "", client: ClientConfig{ID: "a", IDTokenSignedResponseAlg: "none"}, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfiguredClients(&Config{
				Keys:    KeysConfig{Signing: SigningConfig{Alg: tc.signAlg}},
				Clients: []ClientConfig{tc.client},
			})
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "id_token_signed_response_alg") {
					t.Fatalf("err=%v, want id_token_signed_response_alg validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateConfiguredClients() error = %v", err)
			}
		})
	}
}

func TestValidateConfiguredClientsRedirectURIPatterns(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		wantErr  bool
	}{
		{name: "unset"},
		{name: "valid", patterns: []string{"https://app.example.test/tenant/*/callback"}},
		{name: "invalid partial wildcard", patterns: []string{"https://app.example.test/*-callback"}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfiguredClients(&Config{Clients: []ClientConfig{{
				ID:                  "portal",
				RedirectURIPatterns: test.patterns,
			}}})
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "redirect_uri_patterns") {
					t.Fatalf("err=%v, want redirect_uri_patterns validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateConfiguredClients() error = %v", err)
			}
		})
	}
}
