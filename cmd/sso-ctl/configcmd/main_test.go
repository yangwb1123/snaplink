package configcmd

import (
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
