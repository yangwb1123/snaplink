package main

import "testing"

func TestLoadConfig_HTTPDefaultsAndEnvFallback(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"SSO_MCP_JWKS_URL": "https://sso/.well-known/jwks.json",
		"SSO_MCP_RESOURCE": "https://mcp/",
		"SSO_MCP_ISSUER":   "https://sso",
	}
	c, err := loadConfig(nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Transport != transportHTTP {
		t.Errorf("Transport = %q, want http", c.Transport)
	}
	if c.Listen != defaultListen {
		t.Errorf("Listen = %q, want %q", c.Listen, defaultListen)
	}
	if c.RequiredScope != defaultRequiredScope {
		t.Errorf("RequiredScope = %q, want %q", c.RequiredScope, defaultRequiredScope)
	}
	if c.SnaplinkGRPC != defaultSnaplinkGRPC {
		t.Errorf("SnaplinkGRPC = %q, want %q", c.SnaplinkGRPC, defaultSnaplinkGRPC)
	}
}

func TestLoadConfig_FlagBeatsEnv(t *testing.T) {
	t.Parallel()
	env := map[string]string{"SSO_MCP_LISTEN": ":1111", "SSO_MCP_JWKS_URL": "https://sso/jwks", "SSO_MCP_RESOURCE": "https://mcp/"}
	c, err := loadConfig([]string{"-listen", ":2222"}, func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if c.Listen != ":2222" {
		t.Errorf("flag should win: Listen = %q", c.Listen)
	}
}

func TestLoadConfig_HTTPRequiresResourceAndJWKS(t *testing.T) {
	t.Parallel()
	if _, err := loadConfig(nil, func(string) string { return "" }); err == nil {
		t.Fatal("http transport without jwks-url/resource must error")
	}
}

func TestLoadConfig_StdioRequiresJWKSOnly(t *testing.T) {
	t.Parallel()
	env := map[string]string{"SSO_MCP_TRANSPORT": "stdio", "SSO_MCP_JWKS_URL": "https://sso/jwks"}
	if _, err := loadConfig(nil, func(k string) string { return env[k] }); err != nil {
		t.Fatalf("stdio with jwks-url should be valid: %v", err)
	}
}

func TestLoadConfig_RejectsUnknownTransport(t *testing.T) {
	t.Parallel()
	env := map[string]string{"SSO_MCP_TRANSPORT": "carrier-pigeon", "SSO_MCP_JWKS_URL": "x"}
	if _, err := loadConfig(nil, func(k string) string { return env[k] }); err == nil {
		t.Fatal("unknown transport must error")
	}
}

func TestNewSnaplinkClient_ConstructsAndCloses(t *testing.T) {
	t.Parallel()
	c, err := newSnaplinkClient(&Config{
		JWKSURL:      "https://sso/.well-known/jwks.json",
		SnaplinkGRPC: "localhost:8081",
	})
	if err != nil {
		t.Fatalf("newSnaplinkClient: %v", err)
	}
	if c.auth == nil || c.authz == nil {
		t.Fatal("clients not wired")
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
