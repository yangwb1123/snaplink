package archgate

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Harness gate (Harness Engineering): per-DIRECTORY fan-out budgets — a
// directory may hold at most maxGoFilesPerDir non-test .go files and at most
// maxSubdirsPerDir immediate subdirectories. Oversized FLAT packages are hard
// for humans and long-running agents to navigate; this nudges new code toward
// cohesive sub-packages instead of an ever-growing flat directory.
//
// Ratchet + frozen-backlog semantics mirror the maintainability gates: dirs
// already over a cap when this gate was introduced are grandfathered with their
// count at introduction (the ceiling). An exempt dir may not grow PAST its
// ceiling, and must be removed from the list once it drops back under the cap,
// so the backlog only ever shrinks. A NEW over-cap dir FAILS — split it.
//
// Reducing an exempt dir means splitting a flat package into cohesive
// sub-packages. For library packages that is a public-API (import-path) change,
// so the existing over-cap dirs are deliberately grandfathered rather than
// force-split; `package main` dirs (cmd/) can be split without breaking
// consumers and should come down first.
//
// Scope: parent-module tree, same skipDirs set as the file-size/complexity
// gates (gen/, nested modules, vendored UI, bin/ are out of scope).
const (
	maxGoFilesPerDir = 10
	maxSubdirsPerDir = 15
)

// dirFileCountExemptions / dirSubdirExemptions are the frozen backlogs of dirs
// over a cap when this gate was introduced (value = count at introduction).
// SHRINK THESE; never grow them, never raise a ceiling. Regenerate after a
// split with:
//
//	SEED_DIRFANOUT=1 go test -run TestSeedDirectoryFanout -v .
var dirFileCountExemptions = map[string]int{
	"cmd/sso-server":                    50,
	"config":                            28,
	"domains/authenticators":            18,
	"domains/federation":                24,
	"infrastructure/defaultimpl":        62,
	"infrastructure/defaultimpl/sqlite": 34,
	"interfaces/snapshot":               14,
	"interfaces/sso":                    54,
	"platform/audit":                    23,
	"protocols/oauth":                   24,
	"protocols/scim":                    19,
	"shared/core":                       21,
}

// "." is the module root: one subdir per architectural layer (shared/domains/
// protocols/platform/interfaces/infrastructure) plus cmd/config/internal/test/
// proto and the tooling dirs (docs/ops/checks/.github/.arch/.prompts). It does
// not shrink — the cap just prevents root sprawl past today's count.
var dirSubdirExemptions = map[string]int{
	".": 20,
}

// dirFanout is one measured directory.
type dirFanout struct {
	rel     string
	goFiles int
	subdirs int
}

// collectDirFanout walks the parent-module tree once and returns, for each
// in-scope directory, its immediate non-test .go file count and its immediate
// (non-skipped) subdirectory count.
func collectDirFanout(t *testing.T) []dirFanout {
	var out []dirFanout
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if path != "." && skipDirs[d.Name()] {
			return filepath.SkipDir
		}
		entries, rerr := os.ReadDir(path)
		if rerr != nil {
			return rerr
		}
		goFiles, subdirs := 0, 0
		for _, e := range entries {
			if e.IsDir() {
				if !skipDirs[e.Name()] {
					subdirs++
				}
				continue
			}
			if strings.HasSuffix(e.Name(), ".go") && !strings.HasSuffix(e.Name(), "_test.go") {
				goFiles++
			}
		}
		out = append(out, dirFanout{rel: filepath.ToSlash(path), goFiles: goFiles, subdirs: subdirs})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

func TestArchitecture_DirectoryFileFanout(t *testing.T) {
	checkDirBudget(t, "go-file", maxGoFilesPerDir,
		func(d dirFanout) int { return d.goFiles }, dirFileCountExemptions)
}

func TestArchitecture_DirectorySubdirFanout(t *testing.T) {
	checkDirBudget(t, "subdir", maxSubdirsPerDir,
		func(d dirFanout) int { return d.subdirs }, dirSubdirExemptions)
}

// checkDirBudget enforces one per-directory fan-out budget with the same
// frozen-ceiling ratchet semantics as the maintainability per-function gates.
func checkDirBudget(t *testing.T, kind string, threshold int, value func(dirFanout) int, exempt map[string]int) {
	dirs := collectDirFanout(t)
	seen := make(map[string]bool, len(exempt))
	var violations, regressions, stale []string

	for _, d := range dirs {
		v := value(d)
		frozen, isExempt := exempt[d.rel]
		if isExempt {
			seen[d.rel] = true
			if v <= threshold {
				stale = append(stale, fmt.Sprintf("%s (%s count now %d <= %d)", d.rel, kind, v, threshold))
			} else if v > frozen {
				regressions = append(regressions, fmt.Sprintf("%s (%s count %d > frozen ceiling %d)", d.rel, kind, v, frozen))
			}
			continue
		}
		if v > threshold {
			violations = append(violations, fmt.Sprintf("%s (%d %s files > %d)", d.rel, v, kind, threshold))
		}
	}
	for rel := range exempt {
		if !seen[rel] {
			stale = append(stale, fmt.Sprintf("%s (exemption for missing dir — remove it)", rel))
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d director(ies) exceed the %s fan-out budget of %d — split the flat package "+
			"into cohesive sub-packages instead of growing it:\n  %s",
			len(violations), kind, threshold, strings.Join(violations, "\n  "))
	}
	if len(regressions) > 0 {
		sort.Strings(regressions)
		t.Errorf("%d exempt director(ies) regressed past their frozen %s ceiling — exempt dirs may "+
			"not grow:\n  %s", len(regressions), kind, strings.Join(regressions, "\n  "))
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("%d %s exemption(s) no longer needed — remove them (the backlog must only "+
			"shrink):\n  %s", len(stale), kind, strings.Join(stale, "\n  "))
	}
}

// Ratchet latch: the directory-fanout backlogs may only SHRINK. Lower these
// caps (only) when you remove exemptions, so a new over-cap dir cannot be
// silently grandfathered.
const (
	maxDirFileExemptions   = 12
	maxDirSubdirExemptions = 1
)

func TestArchitecture_DirectoryFanoutExemptionsDoNotGrow(t *testing.T) {
	if n := len(dirFileCountExemptions); n > maxDirFileExemptions {
		t.Errorf("dirFileCountExemptions grew to %d (cap %d) — split the new flat package into sub-packages instead of grandfathering it.", n, maxDirFileExemptions)
	}
	if n := len(dirSubdirExemptions); n > maxDirSubdirExemptions {
		t.Errorf("dirSubdirExemptions grew to %d (cap %d) — a directory may hold at most %d subdirectories.", n, maxDirSubdirExemptions, maxSubdirsPerDir)
	}
}

// TestSeedDirectoryFanout is a one-shot helper: run with SEED_DIRFANOUT=1 to
// print Go map literals for the current over-cap dirs. Not a gate.
func TestSeedDirectoryFanout(t *testing.T) {
	if os.Getenv("SEED_DIRFANOUT") != "1" {
		t.Skip("set SEED_DIRFANOUT=1 to regenerate the directory-fanout backlogs")
	}
	dirs := collectDirFanout(t)
	emitDirSeed("dirFileCountExemptions", dirs, maxGoFilesPerDir, func(d dirFanout) int { return d.goFiles })
	emitDirSeed("dirSubdirExemptions", dirs, maxSubdirsPerDir, func(d dirFanout) int { return d.subdirs })
}

func emitDirSeed(name string, dirs []dirFanout, threshold int, value func(dirFanout) int) {
	var lines []string
	for _, d := range dirs {
		if v := value(d); v > threshold {
			lines = append(lines, fmt.Sprintf("\t%q: %d,", d.rel, v))
		}
	}
	sort.Strings(lines)
	fmt.Printf("//SEED-BEGIN %s\n%s\n//SEED-END %s\n", name, strings.Join(lines, "\n"), name)
}
