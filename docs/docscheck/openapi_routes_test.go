package docscheck

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	yaml "github.com/goccy/go-yaml"
)

// TestOpenAPIRoutesRegistered is the "OpenAPI operationId -> route" drift
// checker from docs/deferred-backlog.md. It parses every path+method in
// docs/openapi.yaml and confirms each one is actually registered somewhere in
// the Go source (interfaces/sso, which owns every Mount()-time registration,
// and cmd/sso-server, the reference binary openapi.yaml's own header comment
// says the spec's coverage scope tracks — "Coverage scope is now complete for
// every endpoint cmd/sso-server registers in its reference configuration"),
// or via a proto google.api.http annotation (the admin gRPC-gateway surface:
// Snapshot/Release/Tenant/Domain/Client/User/Token/Permission never appear as
// Go route-registration calls at all — grpc-gateway mounts them from the
// .proto rpc definitions).
//
// This is intentionally a source-level scan, not framework introspection:
// route-registration call sites (Router.GET/POST/.../Handle/HandleFunc) are
// found via go/ast, path arguments are resolved through the same
// const/concatenation resolution common_test.go's collectStringConsts uses
// for every OTHER string constant in the repo, and proto HTTP bindings are
// read as plain text. See resolveRegisteredRoutes' doc for exactly what it
// can and cannot resolve.
func TestOpenAPIRoutesRegistered(t *testing.T) {
	consts := collectStringConsts(repoRoot)
	registered, pathOnly := resolveRegisteredRoutes(t, consts)

	oaRoutes, err := parseOpenAPIRoutes(filepath.Join(repoRoot, "docs/openapi.yaml"))
	if err != nil {
		t.Fatalf("parse docs/openapi.yaml: %v", err)
	}
	if len(oaRoutes) < 50 {
		// Sanity floor: a parser regression that silently returns near-zero
		// paths would otherwise make this whole test vacuously pass.
		t.Fatalf("parsed only %d openapi routes from docs/openapi.yaml — parser likely broken", len(oaRoutes))
	}

	var missing, methodMismatch []string
	for _, oa := range oaRoutes {
		np := normalizeRoutePath(oa.path)
		methods, ok := registered[np]
		if !ok {
			if pathOnly[np] {
				continue
			}
			missing = append(missing, fmt.Sprintf("%s %s (looked for a route matching %q among %d registered paths; found none, not even path-only)",
				oa.method, oa.path, np, len(registered)))
			continue
		}
		if methods[""] {
			continue // path is registered with a statically-unresolvable method; accept.
		}
		if !methods[oa.method] {
			methodMismatch = append(methodMismatch, fmt.Sprintf("%s %s (normalized %s): registered methods are %v, not %s",
				oa.method, oa.path, np, sortedKeys(methods), oa.method))
		}
	}
	sort.Strings(missing)
	sort.Strings(methodMismatch)

	if len(missing) > 0 {
		t.Errorf("%d docs/openapi.yaml path(s) have no matching registered route in interfaces/sso, cmd/sso-server, or proto/**/*.proto google.api.http annotations:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
	if len(methodMismatch) > 0 {
		t.Errorf("%d docs/openapi.yaml operation(s) matched a registered PATH but not its HTTP method:\n  %s",
			len(methodMismatch), strings.Join(methodMismatch, "\n  "))
	}

	logUndocumentedRoutes(t, registered, oaRoutes)
}

// logUndocumentedRoutes reports (non-fatally) routes this source scan found
// registered with NO docs/openapi.yaml entry at all. This is the reverse
// direction the backlog entry calls optional ("if that's easy to also
// detect") — kept as t.Logf rather than a failure because fixing it means
// authoring full new request/response schemas, a real judgment call, not a
// mechanical one-line fix; see the task report for the current list.
func logUndocumentedRoutes(t *testing.T, registered map[string]map[string]bool, oaRoutes []openAPIRoute) {
	documented := map[string]bool{}
	for _, oa := range oaRoutes {
		documented[normalizeRoutePath(oa.path)+" "+oa.method] = true
	}
	var undocumented []string
	for path, methods := range registered {
		for m := range methods {
			if m == "" || documented[path+" "+m] {
				continue
			}
			undocumented = append(undocumented, m+" "+path)
		}
	}
	if len(undocumented) == 0 {
		return
	}
	sort.Strings(undocumented)
	t.Logf("INFORMATIONAL (not a failure): %d registered route(s) have no docs/openapi.yaml entry:\n  %s",
		len(undocumented), strings.Join(undocumented, "\n  "))
}

// ---- route-registration scan (Go source) ----

// routeRegistrarDirs are the only places any route is registered anywhere in
// the repo (verified by grep across the whole module): interfaces/sso's
// Mount() and cmd/sso-server's late-bound Handle() calls (WebAuthn ceremony,
// SCIM, push-approval callback, compliance export/erase, DR status). Scanning
// only these two trees — rather than the whole module — keeps this fast and
// avoids false hits from unrelated .GET/.POST-shaped calls elsewhere (e.g.
// interfaces/adapters/*, which just IMPLEMENT the Router interface with a
// `path string` PARAMETER, not a route registration).
//
// Deliberately excluded: cmd/sso-mcp (a separate MCP-protocol binary, out of
// openapi.yaml's own declared scope) and docs/examples (demo apps).
var routeRegistrarDirs = []string{"interfaces/sso", "cmd/sso-server"}

// internalOnlyRoutes: routes deliberately never in docs/openapi.yaml. Empty
// today — every registered route this scan finds already round-trips through
// either the forward or the informational-reverse check above. Kept as a
// named, documented seam (per the task's "no broad catch-all" instruction)
// for the day a genuinely internal-only route needs one, rather than
// loosening resolveRegisteredRoutes itself.
var internalOnlyRoutes = map[string]bool{}

// resolveRegisteredRoutes returns:
//   - registered: normalized path -> set of HTTP methods found for it. A "" key
//     means at least one registration for that path had a method this scanner
//     could not statically resolve (see resolveHandleCall) — such a path is
//     accepted for ANY OpenAPI method, since we have no reliable method
//     evidence to check against.
//   - pathOnly: normalized path known ONLY via the Path*-const naming
//     convention fallback (below), for a call site this scanner could not
//     resolve at all (e.g. a local variable holding a runtime override, as in
//     server_federation.go's mesh_ext_authz path).
func resolveRegisteredRoutes(t *testing.T, consts map[string]string) (registered map[string]map[string]bool, pathOnly map[string]bool) {
	registered = map[string]map[string]bool{}
	add := func(method, path string) {
		if internalOnlyRoutes[path] {
			return
		}
		np := normalizeRoutePath(path)
		if registered[np] == nil {
			registered[np] = map[string]bool{}
		}
		registered[np][method] = true
	}

	fset := token.NewFileSet()
	for _, rel := range routeRegistrarDirs {
		dir := filepath.Join(repoRoot, rel)
		err := walkGoFiles(dir, func(path string) {
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Errorf("parse %s: %v", path, perr)
				return
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					for _, r := range routesFromCall(call, consts) {
						add(r.method, r.path)
					}
				}
				if cl, ok := n.(*ast.CompositeLit); ok {
					if r, ok := routeFromTuple(cl, consts); ok {
						add(r.method, r.path)
					}
				}
				return true
			})
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	for _, r := range scanProtoHTTPRoutes(t) {
		add(r.method, r.path)
	}

	// Path-only convention fallback: every exported Path*-named const (the
	// repo's "no literal leaks" route-path convention, AGENTS.md §4) is a
	// known route even when its call site resolves to a local variable this
	// scanner can't trace (e.g. `path := s.meshExtAuthzPath`). Kept SEPARATE
	// from `registered` so it can never mask a real method mismatch on a path
	// that DOES have precise call-site evidence.
	pathOnly = map[string]bool{}
	for name, val := range consts {
		if strings.HasPrefix(name, "Path") && strings.HasPrefix(val, "/") {
			pathOnly[normalizeRoutePath(val)] = true
		}
	}
	return registered, pathOnly
}

type routeTuple struct{ method, path string }

// routesFromCall recognizes every route-registration call SHAPE actually
// used in this repo (verified by grep across interfaces/sso + cmd/sso-server):
//
//	router.GET/POST/PUT/PATCH/DELETE(path, handler)   — direct verb methods
//	x.Handle(method, path, handler)                   — sso.Server.Handle
//	mux.Handle(path, handler)                          — stdlib ServeMux, 2-arg
//	mux.HandleFunc(path, handler)                      — stdlib ServeMux
//
// The "api" receiver special-case exists because mountAdminSurface is the
// ONLY Group() call site in the whole package (`api := s.router.Group(PathAPIPrefix)`),
// and every admin route-registration helper receives that group through a
// parameter uniformly named `api` — verified by grep, not assumed.
func routesFromCall(call *ast.CallExpr, consts map[string]string) []routeTuple {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	method := sel.Sel.Name
	if httpVerbSet[method] && len(call.Args) >= 1 {
		if p, ok := resolvePathArg(sel, call.Args[0], consts); ok {
			return []routeTuple{{method: method, path: p}}
		}
		return nil
	}
	switch {
	case method == "Handle" && len(call.Args) == 3:
		m, mok := resolveStringExpr(call.Args[0], consts)
		p, pok := resolvePathArg(sel, call.Args[1], consts)
		if !pok {
			return nil
		}
		if !mok || !httpVerbSet[m] {
			m = "" // method present but statically unresolvable/unrecognized
		}
		return []routeTuple{{method: m, path: p}}
	case method == "Handle" && len(call.Args) == 2, method == "HandleFunc" && len(call.Args) == 2:
		if p, ok := resolvePathArg(sel, call.Args[0], consts); ok {
			return []routeTuple{{method: "", path: p}}
		}
	}
	return nil
}

// resolvePathArg resolves a path argument to a "/"-rooted literal, prepending
// the /api/v1 admin-group prefix for the `api.*` receiver convention (see
// routesFromCall's doc).
func resolvePathArg(sel *ast.SelectorExpr, arg ast.Expr, consts map[string]string) (string, bool) {
	p, ok := resolveStringExpr(arg, consts)
	if !ok || !strings.HasPrefix(p, "/") {
		return "", false
	}
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == "api" {
		if prefix, ok := consts["PathAPIPrefix"]; ok {
			p = prefix + p
		}
	}
	return p, true
}

// routeFromTuple recognizes a 2-element UNKEYED composite literal as a route
// registration entry — the shape scim_routes.go's scimRouteTable
// ({http.MethodGet, scimBasePath + "/Users"}) and serverwebauthn's routes
// table ({PathWebAuthnRegistrationBegin, handlerFunc}) both use. Go's
// go/ast.Inspect already recurses into every composite literal in the source
// tree regardless of whether it sits inside an outer slice literal or is
// passed directly as an append() argument (the SCIM Groups rows use the
// latter), so this only ever needs to look at the literal it's given.
func routeFromTuple(cl *ast.CompositeLit, consts map[string]string) (routeTuple, bool) {
	if len(cl.Elts) != 2 {
		return routeTuple{}, false
	}
	if _, keyed := cl.Elts[0].(*ast.KeyValueExpr); keyed {
		return routeTuple{}, false
	}
	v0, ok0 := resolveStringExpr(cl.Elts[0], consts)
	v1, ok1 := resolveStringExpr(cl.Elts[1], consts)
	switch {
	case ok0 && ok1 && httpVerbSet[v0] && strings.HasPrefix(v1, "/"):
		return routeTuple{method: v0, path: v1}, true
	case ok0 && ok1 && httpVerbSet[v1] && strings.HasPrefix(v0, "/"):
		return routeTuple{method: v1, path: v0}, true
	case ok0 && strings.HasPrefix(v0, "/"):
		return routeTuple{method: "", path: v0}, true
	case ok1 && strings.HasPrefix(v1, "/"):
		return routeTuple{method: "", path: v1}, true
	}
	return routeTuple{}, false
}

// ---- proto google.api.http scan ----

// protoHTTPBlockRe finds each `option (google.api.http) = { ... };` block
// (grpc-gateway's REST-binding annotation); protoHTTPVerbRe then pulls every
// verb:"path" pair out of it. Two passes (rather than one line-anchored
// regex) because both single-line (`{ get: "..." }`) and multi-line
// (`{\n  post: "..."\n  body: "*"\n}`) forms are used across proto/admin/v1.
var protoHTTPBlockRe = regexp.MustCompile(`(?s)option\s*\(google\.api\.http\)\s*=\s*\{(.*?)\};`)
var protoHTTPVerbRe = regexp.MustCompile(`\b(get|post|put|patch|delete)\s*:\s*"([^"]+)"`)

func scanProtoHTTPRoutes(t *testing.T) []routeTuple {
	var out []routeTuple
	dir := filepath.Join(repoRoot, "proto")
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".proto") {
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "/proto/google/") {
			return nil // vendored annotations.proto, not a service definition
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Errorf("read %s: %v", path, rerr)
			return nil
		}
		for _, block := range protoHTTPBlockRe.FindAllStringSubmatch(string(data), -1) {
			for _, m := range protoHTTPVerbRe.FindAllStringSubmatch(block[1], -1) {
				out = append(out, routeTuple{method: strings.ToUpper(m[1]), path: m[2]})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	return out
}

// ---- path normalization ----

// paramSegmentRe matches a whole path SEGMENT that names a template
// parameter, in either OpenAPI ("{id}") or the router's own ("_:id_") style.
var paramSegmentRe = regexp.MustCompile(`^(\{[^}]+\}|:[A-Za-z0-9_]+)$`)

// normalizeRoutePath collapses both styles' parameter segments to the same
// "*" placeholder so "/me/mfa/{id}" (OpenAPI) and "/me/mfa/:id" (Go router)
// compare equal regardless of the parameter's chosen name.
func normalizeRoutePath(p string) string {
	parts := strings.Split(p, "/")
	for i, seg := range parts {
		if paramSegmentRe.MatchString(seg) {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- docs/openapi.yaml parsing ----

type openAPIRoute struct{ path, method string }

// parseOpenAPIRoutes reads docs/openapi.yaml's `paths` mapping and returns
// every path+method pair. Uses yaml.MapSlice (an ORDERED map that tolerates
// repeated keys) plus AllowDuplicateMapKey rather than decoding into a plain
// map[string]any: the file previously had a duplicate `/api/v1/admin/tokens/revoke`
// path key (since fixed by giving the bulk-revoke operation its own
// /api/v1/admin/tokens/bulk-revoke path — the collision meant the gRPC-gateway's
// catch-all mount over /api/v1/admin/ silently shadowed the bulk-revoke REST
// handler in the running server). Kept defensively: goccy/go-yaml's default
// map decoding hard-errors on any repeated key, which would make this whole
// test unable to run at all on a future accidental duplicate — worse than
// tolerating it and reporting both operations under it.
func parseOpenAPIRoutes(file string) ([]openAPIRoute, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Paths yaml.MapSlice `yaml:"paths"`
	}
	if err := yaml.UnmarshalWithOptions(data, &doc, yaml.UseOrderedMap(), yaml.AllowDuplicateMapKey()); err != nil {
		return nil, err
	}
	var out []openAPIRoute
	for _, pathEntry := range doc.Paths {
		pathStr, ok := pathEntry.Key.(string)
		if !ok {
			continue
		}
		item, ok := pathEntry.Value.(yaml.MapSlice)
		if !ok {
			continue
		}
		for _, methodEntry := range item {
			name, ok := methodEntry.Key.(string)
			if !ok {
				continue
			}
			method := strings.ToUpper(name)
			if !httpVerbSet[method] {
				continue // "parameters", "$ref", etc — not an HTTP operation
			}
			out = append(out, openAPIRoute{path: pathStr, method: method})
		}
	}
	return out, nil
}
