package ssotest

// B4-4 deploy-tree sweep (T-8(e) / case 16): the strict credential
// mode has EXACTLY ONE flip point in the deploy tree —
// server.require_form_content_type: true under ops/deploy/compose/
// config.yaml. helm, baremetal, k8s, k8s-distributed and the kustomize
// base stay default-off: no other deployment setting may enable the key.
// Documentation references, including copied OpenAPI descriptions, are not
// settings. The key must also be documented in docs/config-reference.md.

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const formOnlyKey = "require_form_content_type"

var formOnlySetting = regexp.MustCompile(`(^|[ {,])["']?require_form_content_type["']?\s*:`)

func isFormOnlySetting(line string) bool {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return false
	}
	if strings.HasPrefix(strings.TrimPrefix(line, "export "), "SSO_SERVER__REQUIRE_FORM_CONTENT_TYPE=") {
		return true
	}
	return formOnlySetting.MatchString(line)
}

func TestFormOnlySettingRecognizesConfigurationNotDocumentation(t *testing.T) {
	for _, line := range []string{"  require_form_content_type: true", `server: {"require_form_content_type": true}`, "SSO_SERVER__REQUIRE_FORM_CONTENT_TYPE=true", "export SSO_SERVER__REQUIRE_FORM_CONTENT_TYPE=true"} {
		if !isFormOnlySetting(line) {
			t.Errorf("missed setting %q", line)
		}
	}
	for _, line := range []string{"# require_form_content_type: true", "`server.require_form_content_type: true`", "Strict wire mode (server.require_form_content_type)", "// require_form_content_type: true"} {
		if isFormOnlySetting(line) {
			t.Errorf("description mistaken for setting %q", line)
		}
	}
}

// repoRoot resolves the repository root from this package's directory
// (test/), stable under any cwd.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(file))
}

func TestDeployTreeRequireFormContentTypeSingleFlipPoint(t *testing.T) {
	root := repoRoot(t)
	deployDir := filepath.Join(root, "ops", "deploy")
	composeConfig := filepath.Join(deployDir, "compose", "config.yaml")

	// (a) Existence-once: the key appears exactly once in the compose
	// server: block, with value true.
	raw, err := os.ReadFile(composeConfig)
	if err != nil {
		t.Fatalf("read compose config: %v", err)
	}
	// The key literal with the true value, directly under server:
	// (two-space indent, sibling of issuer/base_url/listen).
	flip := "  " + formOnlyKey + ": true"
	if !strings.Contains(string(raw), flip) {
		t.Fatalf("%s must contain %q under the server: block", composeConfig, flip)
	}
	if strings.Count(string(raw), formOnlyKey) != 1 {
		t.Errorf("%s: %q must appear exactly once, got %d hits",
			composeConfig, formOnlyKey, strings.Count(string(raw), formOnlyKey))
	}

	// (b) Scan settings in every deploy file, including embedded ConfigMaps
	// and env overrides; descriptive references must not become false flips.
	var hits []string
	err = filepath.WalkDir(deployDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || path == composeConfig {
			return nil
		}
		if filepath.Ext(path) == ".yaml" || filepath.Ext(path) == ".yml" ||
			filepath.Ext(path) == ".env" || filepath.Ext(path) == ".md" ||
			filepath.Ext(path) == ".sh" || filepath.Ext(path) == ".js" {
			if f, err := os.Open(path); err == nil {
				defer func() { _ = f.Close() }()
				scanner := bufio.NewScanner(f)
				for scanner.Scan() {
					if isFormOnlySetting(scanner.Text()) {
						hits = append(hits, path)
						break
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk ops/deploy: %v", err)
	}
	if len(hits) != 0 {
		t.Errorf("flip setting appears outside compose/config.yaml: %v", hits)
	}

	// (c) Documented: the key is documented in docs/config-reference.md.
	docRaw, err := os.ReadFile(filepath.Join(root, "docs", "config-reference.md"))
	if err != nil {
		t.Fatalf("read config-reference.md: %v", err)
	}
	if !strings.Contains(string(docRaw), "server."+formOnlyKey) {
		t.Errorf("docs/config-reference.md must document server.%s", formOnlyKey)
	}
}
