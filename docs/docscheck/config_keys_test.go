package docscheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestConfigBackendKeysDocumented is the "config-key -> docs" drift
// checker from docs/deferred-backlog.md, narrowed to a well-defined,
// self-consistent subset: backend/substrate-selector keys.
//
// docs/config-reference.md is explicitly a CURATED reference ("YAML
// configuration knobs extracted from AGENTS.md" — its own header), not an
// exhaustive schema dump: of the ~550 distinct YAML leaf-field names actually
// parsed by config/, roughly half never appear in the doc at all, by design
// (e.g. every nested CSP-directive/webhook-retry/SPIFFE-claim field the doc
// summarizes in prose instead of enumerating). A literal "every parsed key
// needs a doc entry" check would fail on ~280 fields that are correctly,
// deliberately un-enumerated — that's not drift, it's the doc doing its job.
//
// What IS a well-defined, checkable claim: docs/config-reference.md's own
// "Storage Backend Toggles" intro states "Every store picks its substrate
// via a `backend:` key" — and the doc mentions individual `*.backend`
// keys throughout multiple sections (not only that one table). So this
// checker cross-references EVERY yaml-tagged `*.backend`/`*_backend`/`store`
// leaf field reachable from the root Config struct (config/config.go)
// against every such key mentioned ANYWHERE in docs/config-reference.md
// (not restricted to one table/section — `security.mtls.backend`, for
// instance, is correctly documented in the "Security" section, not "Storage
// Backend Toggles", because it selects a transport mode, not a persistence
// substrate).
func TestConfigBackendKeysDocumented(t *testing.T) {
	codeKeys := backendLikeConfigPaths(t)
	if len(codeKeys) < 20 {
		t.Fatalf("sanity floor tripped: found only %d backend-like Config leaf paths — "+
			"struct-tree flattener likely broken", len(codeKeys))
	}
	docKeys, err := scanConfigDocKeys(filepath.Join(repoRoot, "docs/config-reference.md"))
	if err != nil {
		t.Fatalf("parse docs/config-reference.md: %v", err)
	}

	var codeNotDoc []string
	for k := range codeKeys {
		if docKeys[k] || configKeyDocExceptions[k] {
			continue
		}
		codeNotDoc = append(codeNotDoc, k)
	}
	sort.Strings(codeNotDoc)
	if len(codeNotDoc) > 0 {
		t.Errorf("%d backend-selector config key(s) parsed from the Config struct tree have no mention "+
			"anywhere in docs/config-reference.md (and are not in configKeyDocExceptions): %s",
			len(codeNotDoc), strings.Join(codeNotDoc, ", "))
	}

	var docNotCode []string
	for k := range docKeys {
		if !isBackendLikeLeaf(k) || codeKeys[k] {
			continue
		}
		docNotCode = append(docNotCode, k)
	}
	sort.Strings(docNotCode)
	if len(docNotCode) > 0 {
		t.Errorf("%d docs/config-reference.md backend-selector key(s) do not resolve to any yaml-tagged "+
			"field reachable from config.Config — renamed or removed field, stale doc: %s",
			len(docNotCode), strings.Join(docNotCode, ", "))
	}
}

// configKeyDocExceptions are backend-like leaf paths that are REAL, parseable
// YAML keys but are deliberately undocumented because they are structurally
// inert: OAuthStoreConfig backs auth_code/par/refresh_token identically, but
// its RotationGraceWindow/RotationGraceBackend fields are — per
// config/config_oauth2.go's own doc comment — "Only meaningful for the
// refresh_token store; ignored by other stores." Documenting the auth_code/par
// copies as if they were independently meaningful would be actively
// misleading, so docs/config-reference.md correctly documents only
// oauth.refresh_token.rotation_grace_backend. A NEW backend key must get a
// real doc entry, not grow this list — it exists only for this one
// struct-reuse artifact.
var configKeyDocExceptions = map[string]bool{
	"oauth.auth_code.rotation_grace_backend": true,
	"oauth.par.rotation_grace_backend":       true,
}

// isBackendLikeLeaf matches the repo's own naming conventions for a
// substrate-selector field, observed across every config/config_*.go file:
// `backend`, `store` (network.store), or a `*_backend` suffix
// (session_backend, rotation_grace_backend, revocation_backend).
func isBackendLikeLeaf(dottedPath string) bool {
	last := dottedPath
	if i := strings.LastIndexByte(dottedPath, '.'); i >= 0 {
		last = dottedPath[i+1:]
	}
	return last == "backend" || last == "store" || strings.HasSuffix(last, "_backend")
}

// ---- config/ struct-tree flattener ----

type configField struct {
	yamlName string
	typeName string // struct type name (pointer unwrapped); "" if not resolvable
	isSlice  bool
	inline   bool // yaml:",inline" — fields join the PARENT at the same path level
}

// backendLikeConfigPaths flattens every struct type declared in config/*.go
// (non-test) into dotted yaml paths, starting from Config (config/config.go),
// and returns the subset matching isBackendLikeLeaf. This is pure type-tree
// walking (go/ast, no value/constant resolution needed — unlike the route
// checker) since a config key's existence depends only on its field's
// position in the struct tree, not on any runtime value.
func backendLikeConfigPaths(t *testing.T) map[string]bool {
	structs := parseConfigStructs(t)
	leaves := flattenConfigTree(structs, "Config", "")
	out := map[string]bool{}
	for _, p := range leaves {
		if isBackendLikeLeaf(p) {
			out[p] = true
		}
	}
	return out
}

// parseConfigStructs collects every `type X struct {...}` in config/*.go
// (the directory only — config/etcd, config/schema etc. are separate
// sub-packages that don't feed the Config tree) into name -> fields.
func parseConfigStructs(t *testing.T) map[string][]configField {
	structs := map[string][]configField{}
	fset := token.NewFileSet()
	dir := filepath.Join(repoRoot, "config")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", e.Name(), perr)
			continue
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if st, ok := ts.Type.(*ast.StructType); ok {
					structs[ts.Name.Name] = structFields(st)
				}
			}
		}
	}
	return structs
}

var yamlTagRe = regexp.MustCompile(`yaml:"([^"]*)"`)

// structFields extracts one configField per yaml-tagged struct field.
// Untagged fields (no `yaml:"..."` at all) are skipped — they carry no YAML
// key of their own, so they can never be a doc-checkable leaf.
func structFields(st *ast.StructType) []configField {
	var out []configField
	for _, f := range st.Fields.List {
		if f.Tag == nil {
			continue
		}
		tagVal, _ := strconv.Unquote(f.Tag.Value)
		m := yamlTagRe.FindStringSubmatch(tagVal)
		if m == nil {
			continue
		}
		opts := strings.Split(m[1], ",")
		name := opts[0]
		inline := false
		for _, o := range opts[1:] {
			if o == "inline" {
				inline = true
			}
		}
		typeName, isSlice := unwrapFieldType(f.Type)
		if len(f.Names) == 0 && inline {
			out = append(out, configField{typeName: typeName, inline: true})
			continue
		}
		if name == "" || name == "-" {
			continue
		}
		n := max(len(f.Names), 1)
		for i := 0; i < n; i++ {
			out = append(out, configField{yamlName: name, typeName: typeName, isSlice: isSlice})
		}
	}
	return out
}

// unwrapFieldType returns the named type a field's declared type resolves to
// (stripping pointer/slice wrapping) — used to decide whether to recurse
// into it as a nested struct. Map/selector (foreign package) types return ""
// (never a locally-defined config struct, so always a leaf).
func unwrapFieldType(e ast.Expr) (name string, isSlice bool) {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name, false
	case *ast.StarExpr:
		n, _ := unwrapFieldType(v.X)
		return n, false
	case *ast.ArrayType:
		n, _ := unwrapFieldType(v.Elt)
		return n, true
	}
	return "", false
}

// flattenConfigTree does a BFS from rootType/rootPrefix, joining each field's
// yaml tag onto its parent's dotted path. `inline` fields join at the SAME
// path level as their parent (goccy/go-yaml's `,inline` semantics) rather
// than adding a segment. A field whose type isn't a known local struct (or is
// a slice-of-struct — e.g. `clients []ClientConfig`, whose members aren't
// independently addressable by one dotted key) is a LEAF.
func flattenConfigTree(structs map[string][]configField, rootType, rootPrefix string) []string {
	type node struct{ typeName, prefix string }
	seen := map[node]bool{}
	queue := []node{{rootType, rootPrefix}}
	var leaves []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if seen[cur] {
			continue
		}
		seen[cur] = true
		for _, fd := range structs[cur.typeName] {
			if fd.inline {
				if _, ok := structs[fd.typeName]; ok {
					queue = append(queue, node{fd.typeName, cur.prefix})
				}
				continue
			}
			path := fd.yamlName
			if cur.prefix != "" {
				path = cur.prefix + "." + fd.yamlName
			}
			if !fd.isSlice {
				if _, ok := structs[fd.typeName]; ok {
					queue = append(queue, node{fd.typeName, path})
					continue
				}
			}
			leaves = append(leaves, path)
		}
	}
	return leaves
}

// ---- docs/config-reference.md key extraction ----

// docBacktickTokenRe finds every backtick-quoted span in the doc.
var docBacktickTokenRe = regexp.MustCompile("`([^`]*)`")
var docBraceRe = regexp.MustCompile(`\{([^}]+)\}`)

// dottedKeyRe recognizes a token that LOOKS like a dotted config key path
// (lowercase segments joined by dots, optionally with one {a,b,c} brace
// group) — as opposed to the many other things backticked in this doc
// (code snippets, Go type names, HTTP methods, file paths).
var dottedKeyRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_{},]+)+$`)

// scanConfigDocKeys extracts every config key mentioned anywhere in file,
// expanding the doc's two shorthand conventions:
//
//   - brace expansion: oauth.introspection.{batch_enabled,max_batch_size}
//     -> oauth.introspection.batch_enabled, oauth.introspection.max_batch_size
//   - same-row dot-continuation: config_audit.enabled / .backend / .sqlite.dsn
//     (three separate backtick-quoted tokens on one table row)
//     -> config_audit.enabled, config_audit.backend, config_audit.sqlite.dsn
//     (each ".suffix" token replaces the LAST segment of the previous
//     resolved token on the same line, chaining left to right)
func scanConfigDocKeys(file string) (map[string]bool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		lastKey := ""
		for _, m := range docBacktickTokenRe.FindAllStringSubmatch(line, -1) {
			tok := m[1]
			switch {
			case strings.HasPrefix(tok, ".") && lastKey != "":
				resolved := replaceLastSegment(lastKey, strings.TrimPrefix(tok, "."))
				for _, k := range expandBraceKey(resolved) {
					out[k] = true
				}
				lastKey = resolved
			case dottedKeyRe.MatchString(tok):
				for _, k := range expandBraceKey(tok) {
					out[k] = true
				}
				lastKey = tok
			}
		}
	}
	return out, nil
}

// replaceLastSegment swaps base's final dotted segment for suffix — the
// dot-continuation shorthand's semantics (".backend" after "x.enabled" means
// "x.backend", not "x.enabled.backend").
func replaceLastSegment(base, suffix string) string {
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		base = base[:i]
	} else {
		return suffix
	}
	return base + "." + suffix
}

// expandBraceKey expands ONE `{a,b,c}` group in key into that many literal
// keys (docs/config-reference.md never nests more than one group per key).
func expandBraceKey(key string) []string {
	loc := docBraceRe.FindStringSubmatchIndex(key)
	if loc == nil {
		return []string{key}
	}
	prefix, suffix := key[:loc[2]-1], key[loc[3]+1:]
	var out []string
	for _, opt := range strings.Split(key[loc[2]:loc[3]], ",") {
		out = append(out, prefix+opt+suffix)
	}
	return out
}
