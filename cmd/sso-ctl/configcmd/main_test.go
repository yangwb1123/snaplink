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
	if code := Run([]string{"validate", "--file", writeTemp(t, validConfig)}); code != 0 {
		t.Errorf("validate(valid) exit = %d, want 0", code)
	}
}

func TestRun_InvalidConfig_Sentinel(t *testing.T) {
	bad := strings.Replace(validConfig, "http://localhost:8080\n  base_url", "snaplink-sso\n  base_url", 1)
	if code := Run([]string{"validate", "--file", writeTemp(t, bad)}); code != 1 {
		t.Errorf("validate(sentinel issuer) exit = %d, want 1", code)
	}
}

func TestRun_MissingFileFlagIsUsageError(t *testing.T) {
	if code := Run([]string{"validate"}); code != 2 {
		t.Errorf("validate without --file exit = %d, want 2", code)
	}
}

func TestRun_NoSubcommand(t *testing.T) {
	if code := Run(nil); code != 2 {
		t.Errorf("no subcommand exit = %d, want 2", code)
	}
}

func TestRun_UnknownSubcommand(t *testing.T) {
	if code := Run([]string{"frobnicate"}); code != 2 {
		t.Errorf("unknown subcommand exit = %d, want 2", code)
	}
}

func TestRun_Help(t *testing.T) {
	if code := Run([]string{"-h"}); code != 0 {
		t.Errorf("help exit = %d, want 0", code)
	}
}
