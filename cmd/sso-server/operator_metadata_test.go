package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/config"
)

// fetchDiscovery hits /.well-known/openid-configuration and unmarshals
// into a generic map so the test can assert on individual fields
// without coupling to the SDK's private struct shape.
func fetchDiscovery(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	return doc
}

func TestBuildApp_SupportedACRValuesAppearsInDiscovery(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Server.SupportedACRValues = []string{"urn:mace:incommon:iap:silver", "phr"}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	got, ok := doc["acr_values_supported"].([]any)
	if !ok {
		t.Fatalf("acr_values_supported missing or wrong type: %T", doc["acr_values_supported"])
	}
	if len(got) != 2 {
		t.Errorf("acr_values_supported len = %d want 2", len(got))
	}
}

func TestBuildApp_OperatorMetadataAppearsInDiscovery(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Server.OperatorMetadata = config.OperatorMetadataConfig{
		PolicyURI:            "https://example.com/policy",
		TosURI:               "https://example.com/tos",
		ServiceDocumentation: "https://example.com/docs",
	}

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	for k, want := range map[string]string{
		"op_policy_uri":         "https://example.com/policy",
		"op_tos_uri":            "https://example.com/tos",
		"service_documentation": "https://example.com/docs",
	} {
		if got, _ := doc[k].(string); got != want {
			t.Errorf("%s = %q want %q", k, got, want)
		}
	}
}

func TestBuildApp_IDTokenIssuerWiredByDefault(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	algs, ok := doc["id_token_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("id_token_signing_alg_values_supported missing — oidc.IDTokenIssuer not wired")
	}
	if len(algs) == 0 || algs[0] != "EdDSA" {
		t.Errorf("id_token_signing_alg_values_supported = %v want [EdDSA]", algs)
	}
}

func TestBuildApp_OperatorMetadataOmittedWhenAllEmpty(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	// Leave OperatorMetadata zero-valued.

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()
	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	doc := fetchDiscovery(t, srv.URL)
	for _, k := range []string{"op_policy_uri", "op_tos_uri", "service_documentation"} {
		if _, present := doc[k]; present {
			t.Errorf("%s present in discovery when not configured (omitempty broken)", k)
		}
	}
}
