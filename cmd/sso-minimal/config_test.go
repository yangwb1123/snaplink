package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/buildinfo"
)

func TestRuntimeConfigUsesEnvironmentAndFlags(t *testing.T) {
	env := map[string]string{
		"SSO_MINIMAL_LISTEN":        "127.0.0.1:9090",
		"SSO_MINIMAL_USERNAME":      "env-user",
		"SSO_MINIMAL_USER_PASSWORD": "env-password",
	}
	getenv := func(key string) string { return env[key] }
	cfg, err := parseRuntimeConfig([]string{
		"--username", "flag-user",
		"--scopes", "openid profile",
	}, getenv, ioDiscard{})
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9090" || cfg.Issuer != "http://127.0.0.1:9090" {
		t.Fatalf("address defaults = listen %q issuer %q", cfg.Listen, cfg.Issuer)
	}
	if cfg.User.Username != "flag-user" || cfg.User.Password != "env-password" {
		t.Fatalf("seed precedence = %#v", cfg.User)
	}
	if cfg.Second.ID != defaultSecondID || cfg.Second.RedirectURI != defaultSecondURI {
		t.Fatalf("second RP defaults = %#v", cfg.Second)
	}
}

func TestModulesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handled, code := handleCommand([]string{"modules", "--json"}, &stdout, &stderr)
	if !handled || code != 0 {
		t.Fatalf("modules command = handled %v code %d stderr=%s", handled, code, stderr.String())
	}
	var inventory buildinfo.ModuleInventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if inventory.Program != inventoryProgram ||
		inventory.Profile != defaultCommandProfile {
		t.Fatalf("inventory identity = %#v", inventory)
	}
	for _, module := range []string{
		"sso-prototype-runtime",
		"sso-minimal-runtime",
	} {
		if !contains(inventory.Modules, module) {
			t.Fatalf("inventory missing %s: %v", module, inventory.Modules)
		}
	}
}

func TestPrototypeListenMustRemainLoopback(t *testing.T) {
	_, err := parseRuntimeConfig(
		[]string{"--listen", "0.0.0.0:8080", "--issuer", "https://sso.example"},
		func(string) string { return "" },
		ioDiscard{},
	)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("wildcard listen error = %v, want loopback requirement", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
