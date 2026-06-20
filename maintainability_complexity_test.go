package archgate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Harness gate (Harness Engineering): per-FUNCTION maintainability budgets —
// cyclomatic complexity and function length — enforced as committed tests so
// they run inside `go test` / `make ci` WITHOUT the generative `make harness`
// (checks/complexity.py) stack, which rewrites tracked files and depends on
// gocyclo/gocognit binaries being installed. This mirrors the ratchet +
// frozen-backlog design of TestMaintainability_FileSizeBudget, with two
// improvements over the Python gate it replaces:
//
//   - Whole-module scope. The Python gate's IGNORE_PATTERN excluded ~40
//     directories (federation/ scim/ admin/ config/ cluster/ …), so most of the
//     tree was never measured; and its exemptions matched by SUBSTRING (every
//     *Validate / *Match / *Score was exempt everywhere). This test measures
//     every parent-module function and keys exemptions precisely by file:func.
//   - Frozen ceiling. Each exemption stores the value measured when it was
//     introduced. An exempt function may not regress PAST that ceiling, and must
//     be removed from the list once it drops back under budget. The backlog only
//     ever shrinks.
//
// Scope: parent-module, non-generated, non-test .go files (same skipDirs set as
// the file-size gate). Nested modules (kms/ saml/ redis/ ldap/ …) own their
// go.mod and are out of scope here. Complexity counts the full function body
// INCLUDING nested function literals, so a closure-heavy function is not split
// into artificially small pieces (this can read higher than a per-closure tool
// like gocyclo; the backlog is seeded from THIS counter, so it is internally
// consistent).
const (
	maxFuncComplexity = 15
	maxFuncLines      = 50
)

// funcMetric is one measured top-level function.
type funcMetric struct {
	key   string // "relpath:funcname", e.g. "protocols/oauth/refresh_token.go:(*Server).rotate"
	cyclo int
	lines int
}

// cycloExemptions / funcLenExemptions WERE the frozen backlogs of functions that
// exceeded the budget when this gate was introduced. Each value was the measure
// at introduction (the ceiling). SHRINK THESE LISTS; never grow them, and never
// raise a ceiling. Both are now EMPTY: the entire backlog has been decomposed,
// so EVERY parent-module function is within the cyclo<=15 / lines<=50 budgets.
// A NEW violation must be fixed (extract sub-functions), never re-exempted.
// Regenerate after a refactor with:
//
//	SEED_MAINTAINABILITY=1 go test -run TestSeedMaintainabilityExemptions -v .
var cycloExemptions = map[string]int{}

var funcLenExemptions = map[string]int{}

func TestMaintainability_CyclomaticComplexity(t *testing.T) {
	checkFuncBudget(t, "cyclo", maxFuncComplexity,
		func(m funcMetric) int { return m.cyclo }, cycloExemptions)
}

func TestMaintainability_FunctionLength(t *testing.T) {
	checkFuncBudget(t, "lines", maxFuncLines,
		func(m funcMetric) int { return m.lines }, funcLenExemptions)
}

// checkFuncBudget enforces one per-function budget with frozen-ceiling ratchet
// semantics: new violations fail, exempt functions that regress past their
// frozen ceiling fail, and exemptions that are no longer needed (now under
// budget, or whose function vanished) fail as stale so the list only shrinks.
func checkFuncBudget(t *testing.T, kind string, threshold int, value func(funcMetric) int, exempt map[string]int) {
	metrics := collectFuncMetrics(t)
	seen := make(map[string]bool, len(exempt))
	var violations, regressions, stale []string

	for _, m := range metrics {
		v := value(m)
		frozen, isExempt := exempt[m.key]
		if isExempt {
			seen[m.key] = true
			if v <= threshold {
				stale = append(stale, fmt.Sprintf("%s (%s now %d <= %d)", m.key, kind, v, threshold))
			} else if v > frozen {
				regressions = append(regressions, fmt.Sprintf("%s (%s %d > frozen ceiling %d)", m.key, kind, v, frozen))
			}
			continue
		}
		if v > threshold {
			violations = append(violations, fmt.Sprintf("%s (%s %d > %d)", m.key, kind, v, threshold))
		}
	}
	for key := range exempt {
		if !seen[key] {
			stale = append(stale, fmt.Sprintf("%s (exemption for missing function — remove it)", key))
		}
	}

	if len(violations) > 0 {
		sort.Strings(violations)
		t.Errorf("%d function(s) exceed the %s budget of %d — extract sub-functions "+
			"(see skills/refactor-high-complexity.md) instead of growing the function:\n  %s",
			len(violations), kind, threshold, strings.Join(violations, "\n  "))
	}
	if len(regressions) > 0 {
		sort.Strings(regressions)
		t.Errorf("%d exempt function(s) regressed past their frozen %s ceiling — exempt "+
			"functions may not get worse:\n  %s", len(regressions), kind, strings.Join(regressions, "\n  "))
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("%d %s exemption(s) no longer needed — remove them (the backlog must only "+
			"shrink):\n  %s", len(stale), kind, strings.Join(stale, "\n  "))
	}
}

// collectFuncMetrics parses every in-scope parent-module .go file once and
// returns the cyclomatic complexity and line span of each top-level function.
func collectFuncMetrics(t *testing.T) []funcMetric {
	var out []funcMetric
	fset := token.NewFileSet()
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
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel := filepath.ToSlash(path)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			out = append(out, funcMetric{
				key:   rel + ":" + funcName(fn),
				cyclo: funcComplexity(fn),
				lines: funcLineSpan(fset, fn),
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

// funcComplexity is the standard cyclomatic count (gocyclo algorithm): 1 plus
// one per branching node, walking nested function literals as part of the body.
func funcComplexity(fn *ast.FuncDecl) int {
	c := 1
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			c++
		case *ast.BinaryExpr:
			if s.Op == token.LAND || s.Op == token.LOR {
				c++
			}
		}
		return true
	})
	return c
}

// funcLineSpan is the function's total footprint, from the `func` keyword to the
// closing brace of its body, inclusive.
func funcLineSpan(fset *token.FileSet, fn *ast.FuncDecl) int {
	return fset.Position(fn.End()).Line - fset.Position(fn.Pos()).Line + 1
}

// funcName renders a stable name including the receiver type, e.g.
// "(*Server).handleLogin" or "buildApp".
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return "(" + recvTypeName(fn.Recv.List[0].Type) + ")." + fn.Name.Name
	}
	return fn.Name.Name
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return "*" + recvTypeName(t.X)
	case *ast.IndexExpr: // generic receiver: T[P]
		return recvTypeName(t.X)
	case *ast.IndexListExpr: // generic receiver: T[P, Q]
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// seedMaintainabilityExemptions is a one-shot helper: run with
// SEED_MAINTAINABILITY=1 to print Go map literals for the current backlog. Not a
// gate — it asserts nothing.
func TestSeedMaintainabilityExemptions(t *testing.T) {
	if os.Getenv("SEED_MAINTAINABILITY") != "1" {
		t.Skip("set SEED_MAINTAINABILITY=1 to regenerate exemption backlogs")
	}
	metrics := collectFuncMetrics(t)
	emitSeed("cycloExemptions", metrics, maxFuncComplexity, func(m funcMetric) int { return m.cyclo })
	emitSeed("funcLenExemptions", metrics, maxFuncLines, func(m funcMetric) int { return m.lines })
}

func emitSeed(name string, metrics []funcMetric, threshold int, value func(funcMetric) int) {
	var lines []string
	for _, m := range metrics {
		if v := value(m); v > threshold {
			lines = append(lines, fmt.Sprintf("\t%q: %d,", m.key, v))
		}
	}
	sort.Strings(lines)
	// Markers let an external splice script extract the literal cleanly from
	// stdout without the t.Log file:line prefix.
	fmt.Printf("//SEED-BEGIN %s\n%s\n//SEED-END %s\n", name, strings.Join(lines, "\n"), name)
}

// Ratchet latch: the exemption backlogs may only SHRINK. A contributor cannot
// silence a freshly-introduced violation by ADDING its own exemption in the same
// commit — that pushes the count over the frozen cap and fails the build. Lower
// these caps (only) when you remove exemptions. This closes the ratchet-bypass
// hole so the per-function budgets are binding for NEW code, not just existing.
const (
	maxCycloExemptions   = 0
	maxFuncLenExemptions = 0
)

func TestMaintainability_ExemptionsDoNotGrow(t *testing.T) {
	if n := len(cycloExemptions); n > maxCycloExemptions {
		t.Errorf("cycloExemptions grew to %d (cap %d) — do NOT add a new exemption to grandfather a new function; extract sub-functions instead. Lower the cap only when removing exemptions.", n, maxCycloExemptions)
	}
	if n := len(funcLenExemptions); n > maxFuncLenExemptions {
		t.Errorf("funcLenExemptions grew to %d (cap %d) — extract sub-functions instead of self-exempting a new long function.", n, maxFuncLenExemptions)
	}
}
