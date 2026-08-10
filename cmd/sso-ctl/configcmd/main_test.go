package configcmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfig = `server:
  issuer: http://localhost:8080
  base_url: http://localhost:8080
  listen: ":8080"
  default_token_strategy: jwt
authenticators:
  password: { enabled: true }
`

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun_ValidConfig(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"validate", "--file", writeTemp(t, validConfig)}); code != 0 {
		t.Errorf("validate(valid) exit = %d, want 0", code)
	}
}

func TestRun_InvalidConfig_Sentinel(t *testing.T) {
	t.Parallel()
	bad := strings.Replace(validConfig, "http://localhost:8080\n  base_url", "snaplink-sso\n  base_url", 1)
	if code := Run([]string{"validate", "--file", writeTemp(t, bad)}); code != 1 {
		t.Errorf("validate(sentinel issuer) exit = %d, want 1", code)
	}
}

func TestRun_MissingFileFlagIsUsageError(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"validate"}); code != 2 {
		t.Errorf("validate without --file exit = %d, want 2", code)
	}
}

func TestRun_NoSubcommand(t *testing.T) {
	t.Parallel()
	if code := Run(nil); code != 2 {
		t.Errorf("no subcommand exit = %d, want 2", code)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"frobnicate"}); code != 2 {
		t.Errorf("unknown subcommand exit = %d, want 2", code)
	}
}

func TestRun_Help(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"-h"}); code != 0 {
		t.Errorf("help exit = %d, want 0", code)
	}
}

func TestRun_Schema_Stdout(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"schema"}); code != 0 {
		t.Errorf("schema exit = %d, want 0", code)
	}
}

func TestRun_Schema_OutFile(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "schema.json")
	if code := Run([]string{"schema", "--out", out}); code != 0 {
		t.Fatalf("schema --out exit = %d, want 0", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read schema file: %v", err)
	}
	if !strings.Contains(string(data), `"$schema"`) {
		t.Errorf("schema file does not look like JSON Schema: %s", data)
	}
}

func TestRun_ValidateSchema_ValidConfig(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"validate-schema", "--file", writeTemp(t, validConfig)}); code != 0 {
		t.Errorf("validate-schema(valid) exit = %d, want 0", code)
	}
}

func TestRun_ValidateSchema_UnknownKey(t *testing.T) {
	t.Parallel()
	bad := validConfig + "\nnot_a_real_top_level_key: true\n"
	if code := Run([]string{"validate-schema", "--file", writeTemp(t, bad)}); code != 1 {
		t.Errorf("validate-schema(unknown key) exit = %d, want 1", code)
	}
}

func TestRun_ValidateSchema_MissingFileFlagIsUsageError(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"validate-schema"}); code != 2 {
		t.Errorf("validate-schema without --file exit = %d, want 2", code)
	}
}

func TestRun_ValidateSchema_MissingFile(t *testing.T) {
	t.Parallel()
	if code := Run([]string{"validate-schema", "--file", filepath.Join(t.TempDir(), "nope.yaml")}); code != 1 {
		t.Errorf("validate-schema(missing file) exit = %d, want 1", code)
	}
}

// Eight-row fixture matrix as YAML, for the scope_registry acceptance
// fixtures below. Deliberately NOT the built-in matrix (which gains
// billing:checkout:create): A1's exit-1 depends on this fixture-local
// literal lacking that row, so it must stay eight rows even as the built-in
// table grows.
const matrixYAML = `admin:read, admin:write, billing:payment:order:read, billing:payment:write,
  metering:write, billing:entitlement:read, audit:event:write, admin:*`

// A1 — unregistered client.allowed_scopes under an enabled registry: exit 1,
// stderr names the client id and the offending scope.
func TestRun_Validate_ScopeRegistry_UnregisteredAllowedScope(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
clients:
  - id: tenant-a
    allowed_scopes: [billing:checkout:create]
oauth:
  scope_registry:
    enabled: true
    matrix: [` + matrixYAML + `]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 1 {
		t.Errorf("validate(unregistered allowed_scope) exit = %d, want 1", code)
	}
}

// A2 — duplicate matrix row: exit 1, even with enabled: false.
func TestRun_Validate_ScopeRegistry_DuplicateMatrixRow(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
oauth:
  scope_registry:
    enabled: false
    matrix: [admin:read, admin:read]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 1 {
		t.Errorf("validate(duplicate matrix row) exit = %d, want 1", code)
	}
}

// A3 — complete matrix + registered clients: exit 0, including a :*-matched
// scope (admin:users:read under admin:*) and an extra_scopes entry.
func TestRun_Validate_ScopeRegistry_CompleteMatrix(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
clients:
  - id: console
    allowed_scopes: [admin:read, admin:users:read]
  - id: checkout
    allowed_scopes: [billing:checkout:create]
oauth:
  scope_registry:
    enabled: true
    matrix: [` + matrixYAML + `]
    extra_scopes: [billing:checkout:create]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 0 {
		t.Errorf("validate(complete matrix) exit = %d, want 0", code)
	}
}

// A4 — the generated schema carries the matrix section via reflection.
func TestRun_Schema_ScopeRegistryMatrix(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "schema.json")
	if code := Run([]string{"schema", "--out", out}); code != 0 {
		t.Fatalf("schema exit = %d, want 0", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Properties struct {
			OAuth struct {
				Properties struct {
					ScopeRegistry struct {
						Properties struct {
							Enabled struct {
								Type string `json:"type"`
							} `json:"enabled"`
							Matrix struct {
								Type  string `json:"type"`
								Items struct {
									Type string `json:"type"`
								} `json:"items"`
							} `json:"matrix"`
							ExtraScopes struct {
								Type  string `json:"type"`
								Items struct {
									Type string `json:"type"`
								} `json:"items"`
							} `json:"extra_scopes"`
						} `json:"properties"`
					} `json:"scope_registry"`
				} `json:"properties"`
			} `json:"oauth"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	m := doc.Properties.OAuth.Properties.ScopeRegistry.Properties
	if m.Matrix.Type != "array" || m.Matrix.Items.Type != "string" {
		t.Errorf("matrix schema = %+v, want {type: array, items: {type: string}}", m.Matrix)
	}
	if m.ExtraScopes.Type != "array" || m.ExtraScopes.Items.Type != "string" {
		t.Errorf("extra_scopes schema = %+v, want {type: array, items: {type: string}}", m.ExtraScopes)
	}
	if m.Enabled.Type != "boolean" {
		t.Errorf("enabled schema type = %q, want boolean", m.Enabled.Type)
	}
}

// P1 — config without any scope_registry block: exit 0 (byte-compat pin).
func TestRun_Validate_ScopeRegistry_DefaultOff(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
clients:
  - id: tenant-a
    allowed_scopes: [billing:checkout:create]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 0 {
		t.Errorf("validate(no scope_registry block) exit = %d, want 0", code)
	}
}

// P2 — enabled: false: no membership check; out-of-matrix allowed_scopes
// still validates (the A1 fixture sets enabled: true for that reason).
func TestRun_Validate_ScopeRegistry_DisabledNoMembership(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
clients:
  - id: tenant-a
    allowed_scopes: [billing:checkout:create]
oauth:
  scope_registry:
    enabled: false
    matrix: [` + matrixYAML + `]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 0 {
		t.Errorf("validate(enabled=false) exit = %d, want 0", code)
	}
}

// P3 — malformed matrix with enabled: false: exit 1 (grammar always
// enforced, mirroring the extra_scopes precedent).
func TestRun_Validate_ScopeRegistry_DisabledBadGrammar(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
oauth:
  scope_registry:
    enabled: false
    matrix: ["*"]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 1 {
		t.Errorf("validate(matrix bare \"*\") exit = %d, want 1", code)
	}
}

// P4 — a matrix row equal to a pre-seeded protocol scope (openid) is an
// idempotent no-op, not a duplicate error: exit 0.
func TestRun_Validate_ScopeRegistry_ProtocolScopeRow(t *testing.T) {
	t.Parallel()
	cfg := validConfig + `
clients:
  - id: console
    allowed_scopes: [openid]
oauth:
  scope_registry:
    enabled: true
    matrix: [` + matrixYAML + `, openid]
`
	if code := Run([]string{"validate", "--file", writeTemp(t, cfg)}); code != 0 {
		t.Errorf("validate(protocol-scope matrix row) exit = %d, want 0", code)
	}
}
