package ssotest

// B4-4 deploy-tree sweep (T-8(e) / case 16): the strict credential
// mode has EXACTLY ONE flip point in the deploy tree —
// server.require_form_content_type: true under ops/deploy/compose/
// config.yaml. helm, baremetal, k8s, k8s-distributed and the kustomize
// base stay default-off: the literal must appear in NO other file under
// ops/deploy/. The key must also be documented in
// docs/config-reference.md. Stdlib-only (line scan) — the compose
// server: block is a flat, 2-space-indented YAML block, so no YAML
// parser is needed.

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const formOnlyKey = "require_form_content_type"

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

	// (b) Absence everywhere else: the literal appears in NO other file
	// under ops/deploy/ (helm/baremetal/k8s/k8s-distributed/kustomize and
	// README/env examples all stay default-off).
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
					if strings.Contains(scanner.Text(), formOnlyKey) {
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
		t.Errorf("flip key appears outside compose/config.yaml: %v", hits)
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
