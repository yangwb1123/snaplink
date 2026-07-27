package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestConfigDefaultIssuerIsNonSentinel guards the cmd-side default
// from regressing back to the SDK sentinel. cmd uses
// cfg.Server.Issuer in three places (WithIssuer via ServerOptions,
// WithEd25519Issuer for the JWT iss claim, tracing.WithServiceName);
// if the default were the SDK sentinel, resolveIssuer + the OIDC
// discovery renderer would fall back to requestBaseURL while the
// JWT iss claim kept the literal sentinel — discovery's `issuer`
// field and access tokens' `iss` claim would then disagree, breaking
// every spec-compliant RFC 9068 validator.
func TestConfigDefaultIssuerIsNonSentinel(t *testing.T) {
	t.Parallel()
	cfg := loadIssuerOnlyConfig(t, "")
	if cfg.Server.Issuer == sso.DefaultIssuer {
		t.Errorf("default Server.Issuer = %q (SDK sentinel) — must be a non-sentinel value",
			cfg.Server.Issuer)
	}
	if cfg.Server.Issuer == "" {
		t.Errorf("default Server.Issuer is empty; expected DefaultServerIssuer")
	}
}

// TestConfigRejectsSDKSentinel proves validation refuses an
// explicitly-set "snaplink-sso" issuer. Operators copying old
// reference YAML files get a loud boot error, not a silent
// production-time divergence between JWT iss + discovery issuer.
func TestConfigRejectsSDKSentinel(t *testing.T) {
	t.Parallel()
	path := writeIssuerYAML(t, sso.DefaultIssuer)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected validation error for explicit SDK sentinel issuer")
	}
	if !strings.Contains(err.Error(), "must not equal") {
		t.Errorf("err = %q; want sentinel-rejection message", err)
	}
}

// TestConfigAcceptsRealURLIssuer proves the validation rule fires
// only on the sentinel — a real URL or any other non-sentinel
// string passes.
func TestConfigAcceptsRealURLIssuer(t *testing.T) {
	t.Parallel()
	for _, issuer := range []string{
		"https://sso.example.com",
		"sso-server",
		"my-deployment-id",
	} {
		t.Run(issuer, func(t *testing.T) {
			cfg := loadIssuerOnlyConfig(t, issuer)
			if cfg.Server.Issuer != issuer {
				t.Errorf("Server.Issuer = %q; want %q", cfg.Server.Issuer, issuer)
			}
		})
	}
}

// TestReferenceConfigIssuerIsNotSentinel — the shipped reference
// config MUST not use the SDK sentinel. Pins against a future
// rebase that accidentally restores the old value.
func TestReferenceConfigIssuerIsNotSentinel(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("config.yaml")
	if err != nil {
		t.Fatalf("load reference config: %v", err)
	}
	if cfg.Server.Issuer == sso.DefaultIssuer {
		t.Errorf("reference config server.issuer = %q (SDK sentinel)", cfg.Server.Issuer)
	}
}

// writeIssuerYAML drops a minimum-viable YAML with the given
// issuer to a tempdir file and returns its path.
func writeIssuerYAML(t *testing.T, issuer string) string {
	t.Helper()
	body := "server:\n  issuer: " + issuer + "\nlogging:\n  level: info\n"
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// loadIssuerOnlyConfig drops a near-empty YAML (only logging level
// to keep validate() happy) and loads it through the full
// applyDefaults + validate pipeline. Issuer absent → the
// DefaultServerIssuer kicks in.
func loadIssuerOnlyConfig(t *testing.T, issuer string) *config.Config {
	t.Helper()
	var body string
	if issuer == "" {
		body = "logging:\n  level: info\n"
	} else {
		body = "server:\n  issuer: " + issuer + "\nlogging:\n  level: info\n"
	}
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}
