package archgate

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestArchitecture_DirectoryDepth caps directory nesting at <= 3 levels
// (cognitive-load: a newcomer should grasp the tree without spelunking). The
// layered package tree (layer/package/subpackage) fits in 3; anything deeper is
// flattened (e.g. snapshot/encryption/none -> snapshot/encryptionnone).
//
// Exemptions (deeper nesting is intrinsic / tool-mandated, NOT a cognitive-load
// surface):
//   - any "testdata" subtree — Go build-ignored test fixtures.
//   - "ops/deploy/**" — deployment config with externally-mandated layouts
//     (grafana provisioning requires provisioning/{dashboards,datasources};
//     docker-compose relative mounts; openresty conf.d/lua). Flattening breaks
//     those tools and has no automated test here to verify.
const maxDirDepth = 3

func TestArchitecture_DirectoryDepth(t *testing.T) {
	t.Parallel()
	var violations []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if skipDirs[name] || name == "testdata" || (name != "." && strings.HasPrefix(name, ".")) {
			return filepath.SkipDir // build dirs, test fixtures, and dotfile/tool dirs (.git/.claude/.qwen/...)
		}
		rel := filepath.ToSlash(path)
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(rel, "ops/deploy") {
			return filepath.SkipDir // tool-mandated deployment layout (documented exemption)
		}
		if depth := strings.Count(rel, "/") + 1; depth > maxDirDepth {
			violations = append(violations, fmt.Sprintf("%s (depth %d)", rel, depth))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d director(ies) nested deeper than %d levels — flatten them (merge the leaf into its parent name):\n  %s",
			len(violations), maxDirDepth, strings.Join(violations, "\n  "))
	}
}
