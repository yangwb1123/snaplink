package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/scopecontract"
)

// validateScopeRegistry runs ALWAYS (even when enabled=false) and is
// fail-closed: a malformed extra_scopes entry fails boot loudly instead of
// silently diverging when the fleet-wide flip later turns the block on
// (FM-3/FM-8). This is the config surface of the scope-matrix-v2 registry.
func TestValidateScopeRegistry(t *testing.T) {
	t.Run("absent block is valid", func(t *testing.T) {
		if err := (&Config{}).validateScopeRegistry(); err != nil {
			t.Fatalf("empty config: %v", err)
		}
	})
	t.Run("disabled with malformed extra still fails", func(t *testing.T) {
		// enabled=false must NOT suppress validation — a stale/malformed
		// snapshot fails loudly at the next restart (fail-closed).
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = false
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"*"}
		if err := cfg.validateScopeRegistry(); err == nil {
			t.Fatal("bare \"*\" with enabled=false: want validation error")
		}
	})
	t.Run("non-colon wildcard rejected", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"admin*"}
		if err := cfg.validateScopeRegistry(); err == nil {
			t.Fatal("non-':*' wildcard: want validation error")
		}
	})
	t.Run("empty scope rejected", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{""}
		if err := cfg.validateScopeRegistry(); err == nil {
			t.Fatal("empty scope: want validation error")
		}
	})
	t.Run("exact and domain-star pass", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"tenant:quota:write", "relay:*"}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("valid extra_scopes: %v", err)
		}
	})
	t.Run("error names the key", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"tenant:ok", "*"}
		err := cfg.validateScopeRegistry()
		if err == nil {
			t.Fatal("want error")
		}
		if !strings.Contains(err.Error(), "oauth.scope_registry.extra_scopes") {
			t.Errorf("error should name the config key, got %v", err)
		}
	})
	t.Run("matrix grammar always enforced", func(t *testing.T) {
		// enabled=false must NOT suppress matrix grammar checks — a bare "*"
		// or a non-":*" wildcard row fails loudly before the fleet flip.
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = false
		cfg.OAuth.ScopeRegistry.Matrix = []string{"*"}
		err := cfg.validateScopeRegistry()
		if err == nil {
			t.Fatal("bare \"*\" matrix row with enabled=false: want validation error")
		}
		if !strings.Contains(err.Error(), "oauth.scope_registry.matrix") {
			t.Errorf("error should name the matrix key, got %v", err)
		}
		cfg.OAuth.ScopeRegistry.Matrix = []string{"admin*"}
		if err := cfg.validateScopeRegistry(); err == nil {
			t.Fatal("non-':*' wildcard matrix row: want validation error")
		}
	})
	t.Run("matrix duplicate always enforced", func(t *testing.T) {
		// NewMemory silently dedupes (set semantics), so the duplicate check
		// must be explicit here — and enabled=false must NOT suppress it.
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = false
		cfg.OAuth.ScopeRegistry.Matrix = []string{"admin:read", "admin:read"}
		err := cfg.validateScopeRegistry()
		if err == nil {
			t.Fatal("duplicate matrix row with enabled=false: want validation error")
		}
		if !strings.Contains(err.Error(), `duplicate scope "admin:read"`) {
			t.Errorf("error should name the duplicated scope, got %v", err)
		}
	})
	t.Run("matrix pattern rows are not duplicates", func(t *testing.T) {
		// "admin:*" and "admin:read" are distinct patterns (RFC 6749 scope
		// comparison is exact-string), not duplicates.
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Matrix = []string{"admin:*", "admin:read"}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("distinct pattern rows: %v", err)
		}
	})
	t.Run("membership inactive when disabled", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = false
		cfg.OAuth.ScopeRegistry.Matrix = []string{"admin:read"}
		cfg.Clients = []ClientConfig{{ID: "c1", AllowedScopes: []string{"billing:checkout:create"}}}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("disabled: membership must not run, got %v", err)
		}
	})
	t.Run("membership rejects unregistered allowed_scope", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = true
		cfg.OAuth.ScopeRegistry.Matrix = scopecontract.Matrix()
		// tenant-quota:projection:write (shared/core const) is deliberately
		// NOT a matrix row — the rebase target that stays unregistered even
		// after billing:checkout:create joins the built-in table.
		cfg.Clients = []ClientConfig{{ID: "tenant-a", AllowedScopes: []string{"tenant-quota:projection:write"}}}
		err := cfg.validateScopeRegistry()
		if err == nil {
			t.Fatal("unregistered allowed_scope with enabled=true: want validation error")
		}
		for _, want := range []string{"tenant-a", "tenant-quota:projection:write", "oauth.scope_registry"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error should name %q, got %v", want, err)
			}
		}
	})
	t.Run("membership accepts built-in matrix checkout row", func(t *testing.T) {
		// billing:checkout:create is now a built-in matrix row: a client
		// allowlisting it passes with an unprovisioned Matrix().
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = true
		cfg.OAuth.ScopeRegistry.Matrix = scopecontract.Matrix()
		cfg.Clients = []ClientConfig{{ID: "checkout", AllowedScopes: []string{"billing:checkout:create"}}}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("matrix-registered allowed_scope: %v", err)
		}
	})
	t.Run("membership accepts matrix, protocol, extra and wildcard", func(t *testing.T) {
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = true
		cfg.OAuth.ScopeRegistry.Matrix = append(scopecontract.Matrix(), "openid")
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"billing:checkout:create"}
		cfg.Clients = []ClientConfig{
			{ID: "console", AllowedScopes: []string{"admin:read", "admin:users:read"}}, // admin:* row
			{ID: "checkout", AllowedScopes: []string{"billing:checkout:create", "openid"}},
		}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("registered allowed_scopes: %v", err)
		}
	})
	t.Run("matrix protocol-scope row idempotent", func(t *testing.T) {
		// A matrix row equal to a pre-seeded protocol scope is a harmless
		// no-op (registry set semantics), never a duplicate error.
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = true
		cfg.OAuth.ScopeRegistry.Matrix = append(scopecontract.Matrix(), "openid")
		cfg.Clients = []ClientConfig{{ID: "c1", AllowedScopes: []string{"openid"}}}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("protocol-scope row: %v", err)
		}
	})
	t.Run("cross-list duplication idempotent", func(t *testing.T) {
		// Same scope in matrix and extra_scopes is set-deduplicated by
		// NewMemory — not a duplicate error.
		cfg := &Config{}
		cfg.OAuth.ScopeRegistry.Enabled = true
		cfg.OAuth.ScopeRegistry.Matrix = []string{"billing:checkout:create"}
		cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"billing:checkout:create"}
		cfg.Clients = []ClientConfig{{ID: "c1", AllowedScopes: []string{"billing:checkout:create"}}}
		if err := cfg.validateScopeRegistry(); err != nil {
			t.Fatalf("cross-list duplicate: %v", err)
		}
	})
}

// MatrixOrDefault must never disagree with the registry construction site:
// absent and explicit-empty both fall back to the built-in nine-scope table;
// a present matrix is returned verbatim.
func TestScopeRegistryConfigMatrixOrDefault(t *testing.T) {
	builtin := scopecontract.Matrix()
	if got := (ScopeRegistryConfig{}).MatrixOrDefault(); !reflect.DeepEqual(got, builtin) {
		t.Errorf("absent matrix: got %v, want built-in %v", got, builtin)
	}
	if got := (ScopeRegistryConfig{Matrix: []string{}}).MatrixOrDefault(); !reflect.DeepEqual(got, builtin) {
		t.Errorf("empty matrix: got %v, want built-in %v", got, builtin)
	}
	provisioned := []string{"custom:scope", "relay:*"}
	if got := (ScopeRegistryConfig{Matrix: provisioned}).MatrixOrDefault(); !reflect.DeepEqual(got, provisioned) {
		t.Errorf("present matrix: got %v, want %v", got, provisioned)
	}
}

// Full-config path: the registry validation is wired into Config.validate so
// --validate-only and boot both exercise it.
func TestValidateIncludesScopeRegistry(t *testing.T) {
	cfg := &Config{}
	cfg.Version = CurrentSchemaVersion
	cfg.Server.Issuer = "https://sso.example.com"
	cfg.OAuth.ScopeRegistry.Enabled = true
	cfg.OAuth.ScopeRegistry.ExtraScopes = []string{"*"}
	if err := cfg.validate(); err == nil {
		t.Fatal("validate() with bare \"*\" extra_scopes: want error")
	}
}
