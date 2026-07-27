package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestEditionCapabilities(t *testing.T) {
	tests := []struct {
		profile string
		edition runtimeEdition
		scopes  string
		oidc    bool
	}{
		{"prototype", editionPrototype, "profile,email", false},
		{"minimal", editionMinimal, "openid,profile,email", true},
		{"standard", editionMinimal, "openid,profile,email", true},
	}
	for _, test := range tests {
		got := editionForProfile(test.profile)
		if got != test.edition ||
			defaultScopesForEdition(got) != test.scopes ||
			got.oidcEnabled() != test.oidc {
			t.Errorf("%s capabilities = %s %s %v", test.profile,
				got, defaultScopesForEdition(got), got.oidcEnabled())
		}
	}
}

func TestPrototypeExposesOAuthWithoutOIDC(t *testing.T) {
	server, cfg := editionServer(t, editionPrototype)
	assertStatus(t, server.URL+sso.PathOIDCDiscovery, http.StatusNotFound)
	assertStatus(t, server.URL+sso.PathUserInfo, http.StatusNotFound)
	assertTracingHeaders(t, server.URL+sso.PathHealth, false)
	metadata := getJSON(t,
		server.URL+sso.PathOAuthAuthorizationServerMetadata, "")
	if metadata["subject_types_supported"] != nil {
		t.Fatalf("OAuth metadata contains OIDC fields: %v", metadata)
	}
	code := loginForCode(t, server.URL, cfg, testVerifier)
	tokens := exchangeCode(t, server.URL, cfg, code, testVerifier)
	if tokens["access_token"] == nil || tokens["id_token"] != nil {
		t.Fatalf("prototype token response = %v", tokens)
	}
}

func TestMinimalAddsOIDCAndTracing(t *testing.T) {
	server, cfg := editionServer(t, editionMinimal)
	assertStatus(t, server.URL+sso.PathOIDCDiscovery, http.StatusOK)
	code := loginForCode(t, server.URL, cfg, testVerifier)
	tokens := exchangeCode(t, server.URL, cfg, code, testVerifier)
	if tokens["id_token"] == nil {
		t.Fatalf("minimal token response = %v", tokens)
	}
	assertTracingHeaders(t, server.URL+sso.PathHealth, true)
}

func assertTracingHeaders(t *testing.T, endpoint string, want bool) {
	t.Helper()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("health request: %v", err)
	}
	defer resp.Body.Close()
	hasHeaders := resp.Header.Get(sso.HeaderRequestID) != "" &&
		resp.Header.Get(sso.HeaderTraceparent) != ""
	if hasHeaders != want {
		t.Fatalf("tracing headers present = %v, want %v: %v",
			hasHeaders, want, resp.Header)
	}
}

func TestDefaultTenantIsStableMigrationAnchor(t *testing.T) {
	store, err := newDefaultTenantStore(context.Background())
	if err != nil {
		t.Fatalf("default tenant store: %v", err)
	}
	got, err := store.GetTenant(context.Background(), defaultTenantID)
	if err != nil {
		t.Fatalf("get default tenant: %v", err)
	}
	if got.ID != "default" || got.Status != tenant.StatusActive {
		t.Fatalf("default tenant = %#v", got)
	}
	if client := seedClient(clientSeed{ID: "client"}); client.TenantID != got.ID {
		t.Fatalf("client tenant = %q, want %q", client.TenantID, got.ID)
	}
}

func TestJSONLoggerCarriesTraceID(t *testing.T) {
	var output bytes.Buffer
	ctx := spi.ContextWithTraceID(context.Background(), "trace-123")
	newJSONLogger(&output).InfoCtx(ctx, "signed in", "user_id", "alice")
	record := map[string]any{}
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	if record["trace_id"] != "trace-123" || record["msg"] != "signed in" {
		t.Fatalf("JSON log = %v", record)
	}
}

func editionServer(
	t *testing.T,
	edition runtimeEdition,
) (*httptest.Server, runtimeConfig) {
	t.Helper()
	cfg := defaultsFromEnv(func(string) string { return "" })
	cfg.Edition = edition
	cfg.Issuer = "https://issuer.example"
	scopes := strings.Split(defaultScopesForEdition(edition), ",")
	cfg.Client.Scopes, cfg.Second.Scopes = scopes, append([]string(nil), scopes...)
	app, err := buildHandler(cfg)
	if err != nil {
		t.Fatalf("build handler: %v", err)
	}
	server := httptest.NewServer(app)
	t.Cleanup(server.Close)
	return server, cfg
}

func assertStatus(t *testing.T, endpoint string, want int) {
	t.Helper()
	resp, err := http.Get(endpoint)
	if err != nil {
		t.Fatalf("GET %s: %v", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("GET %s = %d, want %d", endpoint, resp.StatusCode, want)
	}
}
