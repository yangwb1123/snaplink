// Package docscheck holds committed doc/code drift CI checkers: they run as
// ordinary `go test` targets (picked up by `go test ./...` / `make ci`) so
// docs/openapi.yaml, docs/error-codes.md, and docs/config-reference.md can
// never silently rot behind the Go source the way a purely-manual review
// convention (AGENTS.md "Error codes: New Err* -> update docs/error-codes.md
// in same commit") eventually does. See docs/deferred-backlog.md's "Doc/code
// drift CI checkers" entry.
//
// Every checker here is read-only static analysis (go/ast + regex + YAML
// parsing) against the CURRENT source tree — no framework introspection, no
// running server. That keeps the checkers fast, dependency-free (reusing the
// repo's existing github.com/goccy/go-yaml, never adding a new module), and
// exactly as trustworthy as the source they read.
package docscheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
)

// repoRoot is relative to this package's directory (docs/docscheck), which
// `go test` always runs from — same convention as
// platform/metrics/alert_rules_test.go's "../../ops/deploy/..." paths.
const repoRoot = "../.."

// skipDirs mirrors the root maintainability_budget_test.go's set: directories
// that are generated, vendored, nested modules (own go.mod), or — specific to
// this checker package — OTHER worktree checkouts nested under .claude, which
// would otherwise make every full-repo walk below double-count (or triple, or
// worse) the entire source tree.
var skipDirs = map[string]bool{
	"gen": true, ".claude": true, ".git": true, "web": true, "node_modules": true,
	"dist": true, "bin": true, ".superpowers": true, ".ai": true,
	"kms": true, "redis": true, "postgres": true, "saml": true, "ldap": true,
	"extauthz": true, "kerberos": true, "radius": true,
}

// walkGoFiles calls fn for every non-generated, non-test .go file under root,
// skipping skipDirs. Shared by the const/route scanners below.
func walkGoFiles(root string, fn func(path string)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
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
		fn(path)
		return nil
	})
}

// httpVerbSet is the set of HTTP methods every checker below cares about.
var httpVerbSet = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "CONNECT": true, "OPTIONS": true, "TRACE": true,
}

// httpMethodConstName maps net/http's Method* selector names (as they appear
// in source, e.g. `http.MethodPost`) to their wire verb — used to resolve
// route-registration call sites that pass the stdlib constant instead of a
// literal string.
var httpMethodConstName = map[string]string{
	"MethodGet": "GET", "MethodHead": "HEAD", "MethodPost": "POST", "MethodPut": "PUT",
	"MethodPatch": "PATCH", "MethodDelete": "DELETE", "MethodConnect": "CONNECT",
	"MethodOptions": "OPTIONS", "MethodTrace": "TRACE",
}

// collectStringConsts builds a flat name->value map of every top-level or
// function-local const/var string declaration under root (fixed-point
// iterated so a const defined in terms of another resolves regardless of scan
// order). This is deliberately a flat, whole-module namespace rather than a
// scoped one: the repo's own "No literal leaks — paths/headers/error codes in
// consts.go" convention (AGENTS.md §4) means route-path and error-code
// constants are named uniquely enough (PathAdminTokenRevoke, ErrInvalidGrant,
// ...) that cross-package name collisions are not a real risk in practice,
// and a flat map is far simpler than reproducing Go's full scoping rules for
// a CI checker.
func collectStringConsts(root string) map[string]string {
	consts := map[string]string{}
	fset := token.NewFileSet()
	for iter := 0; iter < 5; iter++ {
		changed := false
		walkGoFiles(root, func(path string) {
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if applyConstDecl(n, consts) {
					changed = true
				}
				return true
			})
		})
		if !changed {
			break
		}
	}
	return consts
}

// applyConstDecl records every name = value pair in a const/var GenDecl into
// consts, returning true if it added or changed anything (drives the
// fixed-point loop in collectStringConsts).
func applyConstDecl(n ast.Node, consts map[string]string) bool {
	gd, ok := n.(*ast.GenDecl)
	if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
		return false
	}
	changed := false
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			continue
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) {
				continue
			}
			val, ok := resolveStringExpr(vs.Values[i], consts)
			if !ok {
				continue
			}
			if old, exists := consts[name.Name]; !exists || old != val {
				consts[name.Name] = val
				changed = true
			}
		}
	}
	return changed
}

// resolveStringExpr best-effort evaluates e to a string: a literal, a
// known identifier/selector (looked up in consts or the net/http Method*
// table), or a "+"-concatenation of two such resolvable sides. Anything
// requiring real dataflow (a struct field read, a function call result)
// intentionally fails to resolve — callers treat that as "unknown", not "no
// route", per the fallback conventions documented at each call site.
func resolveStringExpr(e ast.Expr, consts map[string]string) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			return s, err == nil
		}
	case *ast.Ident:
		val, ok := consts[v.Name]
		return val, ok
	case *ast.SelectorExpr:
		if m, ok := httpMethodConstName[v.Sel.Name]; ok {
			return m, true
		}
		val, ok := consts[v.Sel.Name]
		return val, ok
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			l, lok := resolveStringExpr(v.X, consts)
			r, rok := resolveStringExpr(v.Y, consts)
			if lok && rok {
				return l + r, true
			}
		}
	case *ast.ParenExpr:
		return resolveStringExpr(v.X, consts)
	}
	return "", false
}
