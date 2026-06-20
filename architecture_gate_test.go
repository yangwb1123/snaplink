package archgate

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Harness gate (architecture_violation: 0): enforce the dependency-direction
// invariants AGENTS.md declares, as a committed test riding the existing
// `go test`/`make ci` gate. Import cycles and leaf-package erosion are the
// architectural failures a long-running agent introduces silently; the compiler
// only catches *cycles*, not the one-way rule violations or leaf erosion that
// precede them.
//
// Each rule forbids files under fromDir from importing anything whose path has
// the forbidden prefix. Pre-existing violations are grandfathered per-rule in
// `exempt` (a ratchet — the list may only shrink; no NEW violations may land).
type importRule struct {
	fromDir   string          // relative dir prefix, e.g. "oauth/"
	forbidden string          // forbidden import-path prefix
	why       string          // AGENTS.md rationale
	exempt    map[string]bool // grandfathered files (relative, slash paths)
}

var importRules = []importRule{
	{
		fromDir:   "protocols/oauth/",
		forbidden: "github.com/snaplink/sso/protocols/oidc",
		why:       "oauth MUST NOT import oidc — would create the oauth<->oidc cycle (AGENTS.md §Coding Conventions)",
	},
	{
		fromDir:   "protocols/oidc/",
		forbidden: "github.com/snaplink/sso/protocols/oauth",
		why:       "oidc MUST NOT import oauth (AGENTS.md §2 OIDC Layer). The two formerly-grandfathered files were decoupled (oidc.SubjectRefreshRevoker for refresh revocation; core.CloneRawJSON for RAR cloning), so this rule now has ZERO exemptions.",
	},
	{
		fromDir:   "shared/core/",
		forbidden: "github.com/snaplink/sso/",
		why:       "core is the dependency-free SPI/types/sentinels leaf — it must import NO internal package (AGENTS.md §1 package layout)",
	},
}

func TestArchitecture_ImportBoundaries(t *testing.T) {
	fset := token.NewFileSet()
	var violations, staleExempt []string
	hitExempt := map[string]bool{}

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel := filepath.ToSlash(path)
		var matched []importRule
		for _, r := range importRules {
			if strings.HasPrefix(rel, r.fromDir) {
				matched = append(matched, r)
			}
		}
		if len(matched) == 0 {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", rel, perr)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, r := range matched {
				if !strings.HasPrefix(p, r.forbidden) {
					continue
				}
				// core's rule forbids the whole internal prefix; don't flag a
				// file importing its OWN package (can't happen) — and allow the
				// exact root module path only via explicit prefix semantics.
				if r.exempt[rel] {
					hitExempt[rel+"|"+r.forbidden] = true
					continue
				}
				violations = append(violations, fmt.Sprintf("%s imports %q — %s", rel, p, r.why))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d architecture import-boundary violation(s):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
	// Ratchet: an exemption that's no longer exercised (import removed) must be
	// dropped so the grandfather list only shrinks.
	for _, r := range importRules {
		for rel := range r.exempt {
			if !hitExempt[rel+"|"+r.forbidden] {
				staleExempt = append(staleExempt, fmt.Sprintf("%s (no longer imports %s)", rel, r.forbidden))
			}
		}
	}
	if len(staleExempt) > 0 {
		sort.Strings(staleExempt)
		t.Errorf("%d stale architecture exemption(s) — remove from importRules.exempt:\n  %s",
			len(staleExempt), strings.Join(staleExempt, "\n  "))
	}
}
