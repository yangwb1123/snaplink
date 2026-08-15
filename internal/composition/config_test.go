package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/buildinfo"
	"github.com/yangwb1123/snaplink/shared/spi"
)

var testEditions = []Edition{
	{
		Profile:       "prototype",
		OIDC:          false,
		DefaultScopes: "profile,email",
		Modules:       []string{"core-runtime", "sso-prototype-runtime"},
		Capabilities: []string{
			"config.host.v1", "core.runtime.v1", "lifecycle.host.v1",
			"oauth.sso-prototype.v1", "observability.logging.v1",
			"security.policy.v1", "server.sso-prototype.v1", "tenant.default.v1",
		},
	},
	{
		Profile:       "minimal",
		OIDC:          true,
		DefaultScopes: "openid,profile,email",
		Modules: []string{
			"core-runtime", "sso-prototype-runtime", "sso-minimal-runtime",
		},
		Capabilities: []string{
			"config.host.v1", "core.runtime.v1", "lifecycle.host.v1",
			"oauth.sso-prototype.v1", "observability.logging.v1",
			"observability.tracing.v1", "oidc.common.v1", "security.policy.v1",
			"server.sso-minimal.v1", "server.sso-prototype.v1", "tenant.default.v1",
		},
	},
}

func TestRuntimeConfigUsesEnvironmentAndFlags(t *testing.T) {
	env := map[string]string{
		"SSO_MINIMAL_LISTEN":        "127.0.0.1:9090",
		"SSO_MINIMAL_USERNAME":      "env-user",
		"SSO_MINIMAL_USER_PASSWORD": "env-password",
	}
	getenv := func(key string) string { return env[key] }
	cfg, err := ParseRuntimeConfig([]string{
		"--username", "flag-user",
		"--scopes", "openid profile",
	}, getenv, io.Discard, testEditions[1])
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9090" || cfg.Issuer != "http://127.0.0.1:9090" {
		t.Fatalf("address defaults = listen %q issuer %q", cfg.Listen, cfg.Issuer)
	}
	if cfg.User.Username != "flag-user" || cfg.User.Password != "env-password" {
		t.Fatalf("seed precedence = %#v", cfg.User)
	}
	if cfg.Second.ID != DefaultSecondID || cfg.Second.RedirectURI != DefaultSecondURI {
		t.Fatalf("second RP defaults = %#v", cfg.Second)
	}
}

func TestModulesJSONPerEdition(t *testing.T) {
	for _, edition := range testEditions {
		var stdout, stderr bytes.Buffer
		handled, code := HandleCommand([]string{"modules", "--json"}, &stdout, &stderr, edition)
		if !handled || code != 0 {
			t.Fatalf("%s modules command = handled %v code %d stderr=%s",
				edition.Profile, handled, code, stderr.String())
		}
		var inventory buildinfo.ModuleInventory
		if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil {
			t.Fatalf("decode inventory: %v", err)
		}
		if inventory.Program != ProgramName || inventory.Profile != edition.Profile {
			t.Fatalf("%s inventory identity = %#v", edition.Profile, inventory)
		}
		if len(inventory.Modules) != len(edition.Modules) {
			t.Fatalf("%s inventory modules = %v, want %v",
				edition.Profile, inventory.Modules, edition.Modules)
		}
		for _, module := range edition.Modules {
			if !contains(inventory.Modules, module) {
				t.Fatalf("%s inventory missing %s: %v",
					edition.Profile, module, inventory.Modules)
			}
		}
	}
}

func TestPrototypeListenMustRemainLoopback(t *testing.T) {
	for _, edition := range testEditions {
		_, err := ParseRuntimeConfig(
			[]string{"--listen", "0.0.0.0:8080", "--issuer", "https://sso.example"},
			func(string) string { return "" },
			io.Discard,
			edition,
		)
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("%s wildcard listen error = %v, want loopback requirement",
				edition.Profile, err)
		}
	}
}

func TestOpenidScopeRequirementFollowsEdition(t *testing.T) {
	_, err := ParseRuntimeConfig(
		[]string{"--scopes", "profile"},
		func(string) string { return "" },
		io.Discard,
		Edition{Profile: "minimal", OIDC: true, DefaultScopes: "openid,profile,email"},
	)
	if err == nil || !strings.Contains(err.Error(), "openid") {
		t.Fatalf("minimal without openid error = %v, want openid requirement", err)
	}
	if _, err := ParseRuntimeConfig(
		[]string{"--scopes", "profile"},
		func(string) string { return "" },
		io.Discard,
		Edition{Profile: "prototype", OIDC: false, DefaultScopes: "profile,email"},
	); err != nil {
		t.Fatalf("prototype without openid should validate: %v", err)
	}
}

func TestDefaultTenantIsStableMigrationAnchor(t *testing.T) {
	store, err := NewDefaultTenantStore(context.Background())
	if err != nil {
		t.Fatalf("default tenant store: %v", err)
	}
	got, err := store.GetTenant(context.Background(), DefaultTenantID)
	if err != nil {
		t.Fatalf("get default tenant: %v", err)
	}
	if got.ID != "default" || got.Status != tenant.StatusActive {
		t.Fatalf("default tenant = %#v", got)
	}
	if client := seedClient(ClientSeed{ID: "client"}); client.TenantID != got.ID {
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
