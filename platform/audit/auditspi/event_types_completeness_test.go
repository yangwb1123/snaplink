package auditspi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestKnownEventTypesIsComplete is a self-healing completeness guard for
// KnownEventTypes. That map is hand-maintained (added by a sibling task for
// operator-facing filter validation — see its doc comment in
// event_types.go) and therefore drifts silently whenever a LATER, parallel
// task adds a new EventType const without also touching the map: the const
// compiles fine, every existing caller keeps working, and the only symptom
// is downstream consumers of KnownEventTypes treating a real, emitted event
// type as unknown (e.g. the SOC2 evidence report in platform/audit/
// auditreport files it into "Uncategorized" instead of its real control
// area, and the webhook subscription filter UX flags it as a typo). This
// test AST-parses every event_types*.go source file in this package
// (skipping itself and any other _test.go) and fails, naming the exact
// missing constant(s), whenever a declared EventType const's string value
// is absent from KnownEventTypes — so the map self-heals for EVERY
// consumer, not just whichever one happened to notice first.
func TestKnownEventTypesIsComplete(t *testing.T) {
	declared := declaredEventTypeConstValues(t)

	var missing []string
	for _, value := range declared {
		if _, ok := KnownEventTypes[EventType(value)]; !ok {
			missing = append(missing, value)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d EventType const(s) declared in event_types*.go are missing from "+
			"KnownEventTypes (platform/audit/auditspi/event_types.go) — add them:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// declaredEventTypeConstValues AST-parses every event_types*.go file in
// this directory (excluding _test.go files, so it never tries to parse
// itself) and returns the string value of every `Name EventType = "..."`
// const declaration found. Parsing source directly — rather than using
// reflection over the compiled package, which has no way to enumerate "all
// package-level consts of type T" — means a brand-new const is picked up
// the moment it's added, with no separate registration step to forget.
func declaredEventTypeConstValues(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("event_types*.go")
	if err != nil {
		t.Fatalf("glob event_types*.go: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("glob event_types*.go matched no files — test is running from the wrong directory")
	}

	var out []string
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		out = append(out, eventTypeConstsInFile(t, src)...)
	}
	return out
}

// eventTypeConstsInFile walks one parsed file's top-level const blocks and
// collects the string literal value of every spec explicitly typed
// `EventType` — matching this package's own convention (every event_types*.go
// const line spells out `Name EventType = "..."`, never relying on
// iota/type-inference), so no runtime reflection over the const's
// underlying type is needed.
func eventTypeConstsInFile(t *testing.T, src *ast.File) []string {
	t.Helper()
	var out []string
	for _, decl := range src.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			ident, ok := vs.Type.(*ast.Ident)
			if !ok || ident.Name != "EventType" {
				continue
			}
			out = append(out, eventTypeConstValues(t, vs)...)
		}
	}
	return out
}

// eventTypeConstValues unquotes the string literal(s) on one EventType
// ValueSpec. Every const in event_types*.go assigns a plain string
// literal, so a non-string-literal value (e.g. a future refactor to an
// expression) is treated as a hard test failure rather than silently
// skipped — this guard exists precisely to not let a new const slip past
// unnoticed.
func eventTypeConstValues(t *testing.T, vs *ast.ValueSpec) []string {
	t.Helper()
	out := make([]string, 0, len(vs.Values))
	for i, v := range vs.Values {
		lit, ok := v.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			name := "?"
			if i < len(vs.Names) {
				name = vs.Names[i].Name
			}
			t.Fatalf("EventType const %s has a non-string-literal value — completeness guard "+
				"can't statically evaluate it; keep EventType consts as plain string literals", name)
			continue
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquote %s: %v", lit.Value, err)
		}
		out = append(out, s)
	}
	return out
}
