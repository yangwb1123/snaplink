package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-yaml"
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

func TestClientConfigYAMLDecodesPublicAuthMethod(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(`clients:
  - id: spa
    token_endpoint_auth_method: none
    require_pkce: true
`), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].TokenEndpointAuthMethod != "none" || !cfg.Clients[0].RequirePKCE {
		t.Fatalf("decoded client = %+v, want public auth method with PKCE", cfg.Clients)
	}
	if err := validateConfiguredClients(&cfg); err != nil {
		t.Fatalf("validateConfiguredClients() error = %v", err)
	}
}

func TestClientConfigYAMLDecodesGrantTypesAndPreservesUnrestrictedClient(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte(`clients:
  - id: forge-cli
    grant_types:
      - urn:ietf:params:oauth:grant-type:device_code
      - urn:example:grant-type:custom
  - id: sso-admin-console
`), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}
	if len(cfg.Clients) != 2 {
		t.Fatalf("decoded %d clients, want 2", len(cfg.Clients))
	}
	got := cfg.Clients[0].GrantTypes
	if len(got) != 2 || got[0] != "urn:ietf:params:oauth:grant-type:device_code" || got[1] != "urn:example:grant-type:custom" {
		t.Fatalf("forge-cli grant types = %v", got)
	}
	if cfg.Clients[1].ID != "sso-admin-console" || cfg.Clients[1].GrantTypes != nil {
		t.Fatalf("unconfigured admin client = %+v, want nil grant_types", cfg.Clients[1])
	}
	if err := validateConfiguredClients(&cfg); err != nil {
		t.Fatalf("validateConfiguredClients() error = %v", err)
	}
}

func TestDistributedForgeClientGrantProfiles(t *testing.T) {
	cfg, err := Load("../ops/deploy/k8s-distributed/config.yaml")
	if err != nil {
		t.Fatalf("Load distributed profile: %v", err)
	}

	clients := make(map[string]ClientConfig, 2)
	for _, client := range cfg.Clients {
		if client.ID == "forge-cli" || client.ID == "forge-console" {
			clients[client.ID] = client
		}
	}
	cli, ok := clients["forge-cli"]
	if !ok {
		t.Fatal("distributed profile is missing forge-cli")
	}
	console, ok := clients["forge-console"]
	if !ok {
		t.Fatal("distributed profile is missing forge-console")
	}
	if want := []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}; !slices.Equal(cli.GrantTypes, want) {
		t.Errorf("forge-cli grant_types = %v, want %v", cli.GrantTypes, want)
	}
	if want := []string{"authorization_code", "refresh_token"}; !slices.Equal(console.GrantTypes, want) {
		t.Errorf("forge-console grant_types = %v, want unchanged %v", console.GrantTypes, want)
	}
	if got := cfg.OAuth.RefreshToken.RotationGraceWindow; got != 5*time.Second {
		t.Errorf("distributed refresh rotation grace window = %s, want 5s", got)
	}
	if got := cfg.OAuth.RefreshToken.RotationGraceBackend; got != "redis" {
		t.Errorf("distributed refresh rotation grace backend = %q, want redis", got)
	}
}

func TestValidateConfiguredClientGrantTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		grantType []string
		wantErr   bool
	}{
		{name: "unset remains unrestricted"},
		{name: "custom extension accepted", grantType: []string{"urn:example:grant-type:custom"}},
		{name: "empty item rejected", grantType: []string{"authorization_code", ""}, wantErr: true},
		{name: "whitespace item rejected", grantType: []string{"   "}, wantErr: true},
		{name: "padded item rejected", grantType: []string{" authorization_code "}, wantErr: true},
		{name: "duplicate rejected", grantType: []string{"urn:example:grant-type:custom", "urn:example:grant-type:custom"}, wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfiguredClients(&Config{Clients: []ClientConfig{{ID: "client", GrantTypes: test.grantType}}})
			if test.wantErr {
				if err == nil || !strings.Contains(err.Error(), "grant_types") {
					t.Fatalf("err=%v, want grant_types validation error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateConfiguredClients() error = %v", err)
			}
		})
	}
}

func TestValidateConfiguredPublicClientRequiresSecretlessPKCE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		client  ClientConfig
		wantErr bool
	}{
		{name: "default client secret basic", client: ClientConfig{ID: "confidential"}},
		{name: "secretless pkce", client: ClientConfig{ID: "spa", TokenEndpointAuthMethod: "none", RequirePKCE: true}},
		{name: "supported private key jwt", client: ClientConfig{ID: "jwt", TokenEndpointAuthMethod: "private_key_jwt"}},
		{name: "supported tls client auth", client: ClientConfig{ID: "mtls", TokenEndpointAuthMethod: "tls_client_auth"}},
		{name: "supported self signed tls", client: ClientConfig{ID: "self", TokenEndpointAuthMethod: "self_signed_tls"}},
		{name: "secret rejected", client: ClientConfig{ID: "spa", Secret: "not-public", TokenEndpointAuthMethod: "none", RequirePKCE: true}, wantErr: true},
		{name: "pkce required", client: ClientConfig{ID: "spa", TokenEndpointAuthMethod: "none"}, wantErr: true},
		{name: "unsupported method", client: ClientConfig{ID: "spa", TokenEndpointAuthMethod: "client_secret_bearer"}, wantErr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateConfiguredClients(&Config{Clients: []ClientConfig{test.client}})
			if test.wantErr && err == nil {
				t.Fatal("expected public-client validation error")
			}
			if !test.wantErr && err != nil {
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
