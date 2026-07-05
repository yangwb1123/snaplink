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

// Cognitive-architecture layer gate (ADR-0006, docs/architecture/DIRECTORY_MAP.md).
//
// Every main-module package is assigned one of seven layers. The allowed
// dependency direction is one-way toward the shared kernel: a package may import
// only packages in its own layer or a LOWER-rank (more-shared) one. Packages now
// live PHYSICALLY under their layer directory (shared/ domains/ protocols/
// platform/ interfaces/ infrastructure/), so the first path segment IS the layer;
// this gate keeps the dependency direction a CHECKED invariant caught at `go test`
// time. It is the erosion guard the compiler lacks: the compiler stops cycles,
// this stops a domain/protocol package quietly reaching up into infrastructure or
// the HTTP edge. (This test package is `archgate` and lives at the repo root so it
// walks the whole module; the public Server API now lives at interfaces/sso.)
//
//	rank  layer            may be imported by            typical members
//	0     shared           everyone                      core, spi, security
//	1     platform         domains..composition          cluster, metrics, audit(mechanism), geo
//	2     domains          protocols..composition        tenant, permissions, federation, authenticators
//	3     protocols        infrastructure..composition   oauth, oidc, scim, fapi, selfservice
//	4     infrastructure   interfaces, composition        defaultimpl (implements the abstractions)
//	5     interfaces       composition                   grpcserver, adapters, middleware, root Server API
//	6     composition      —                             cmd, config, examples, testkit
//
// Ratchet: the upward edges that existed when this gate landed are grandfathered
// in layerExemptions and may only SHRINK; no NEW upward edge may land.
const layerModuleRoot = "github.com/snaplink/sso"

var layerRank = map[string]int{
	"shared": 0, "platform": 1, "domains": 2, "protocols": 3,
	"infrastructure": 4, "interfaces": 5, "composition": 6,
}

// layerName maps a package's slash path (relative to the module root; "" is the
// root package) to its architectural layer. A NEW top-level package MUST be
// classified here — an unclassified package fails the gate by design, so the
// layer model can never silently drift behind the package list.
func layerName(rel string) string {
	seg := rel
	if i := strings.IndexByte(rel, '/'); i >= 0 {
		seg = rel[:i]
	}
	// composition root: wires concrete implementations; may import anything.
	if strings.HasPrefix(rel, "platform/bootstrap/builtin") {
		return "composition"
	}
	// Packages now live physically under their layer directory (the v2 layered
	// tree), so the first path segment IS the layer for the six library layers.
	switch seg {
	case "shared", "platform", "domains", "protocols", "infrastructure", "interfaces":
		return seg
	case "redis", "postgres":
		// Nested infrastructure modules: their module paths are
		// github.com/snaplink/sso/{redis,postgres} (mapped via replace to
		// ./infrastructure/{redis,postgres}), so a consumer's import strips to
		// the bare segment. The modules' own dirs are skipped by the walk
		// (skipDirs); this only classifies the import target so cmd's
		// composition -> infrastructure edge resolves.
		return "infrastructure"
	case "cmd", "examples", "testkit", "config", "deploy", "test":
		return "composition"
	case "gen", "proto":
		// generated protobuf + REST gateway — inbound/delivery edge.
		return "interfaces"
	}
	if strings.HasPrefix(rel, "docs/examples") {
		// example apps moved under docs/ — composition (wire everything, demo only).
		return "composition"
	}
	if strings.HasPrefix(rel, "docs/docscheck") {
		// doc/code drift CI checkers (_test.go only today, so this walk's own
		// _test.go skip means the gate never actually visits it — classified
		// anyway per AGENTS.md §0.6.6, and so a future non-test helper file
		// here doesn't newly trip "unclassified package"). Composition: it
		// reads the whole tree (routes, error codes, config schema) the same
		// way test/ and cmd/ do, never the reverse.
		return "composition"
	}
	if rel == "docs" {
		// The embedded-OpenAPI-spec package (docs/openapi_embed.go) only — has
		// zero internal imports of its own, so it sits at the kernel rank
		// (shared) rather than composition like docs/examples: both
		// interfaces/apidocs (rank interfaces) and cmd/gensdk (rank
		// composition) need to import it DOWNWARD.
		return "shared"
	}
	if rel == "" {
		// root package: the public Server type + server_*.go HTTP handlers.
		return "interfaces"
	}
	if strings.HasPrefix(rel, "internal/auth") {
		return "domains"
	}
	if strings.HasPrefix(rel, "internal/handler") {
		return "interfaces"
	}
	return "" // unclassified
}

// layerExemptions grandfathers the upward edges present when this gate landed —
// almost all of them the root god-package fan-in (authenticators/defaultimpl
// reaching the root Server type) plus a few cross-cutting couplings. SHRINK
// ONLY. Key: "<fromPkg> -> <toPkg>" where "." denotes the root package.
var layerExemptions = map[string]bool{
	"domains/authenticators -> interfaces/sso":            true, // root Server type + With* options (god-package fan-in)
	"domains/authenticators/webauthn -> interfaces/sso":   true, // ditto
	"infrastructure/defaultimpl -> interfaces/sso":        true, // concrete impls reference root-package types
	"infrastructure/defaultimpl/sqlite -> interfaces/sso": true, // ditto
	"platform/audit -> domains/region":                    true, // event enrichment reads region from request ctx
	"platform/audit -> domains/tenant":                    true, // event enrichment reads tenant from request ctx
	"protocols/oauth -> interfaces/middleware":            true, // trusted-proxy / real-client-IP helper
	"protocols/scim -> interfaces/admin":                  true, // SCIM endpoints require the admin scope gate
	"protocols/selfservice -> interfaces/middleware":      true, // real-client-IP helper
}

func TestArchitecture_LayerBoundaries(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	violations := map[string]bool{}
	unclassified := map[string]bool{}
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
		dir := filepath.ToSlash(filepath.Dir(path))
		if dir == "." {
			dir = ""
		}
		from := layerName(dir)
		if from == "" {
			unclassified[layerDisp(dir)] = true
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p != layerModuleRoot && !strings.HasPrefix(p, layerModuleRoot+"/") {
				continue
			}
			toRel := strings.TrimPrefix(strings.TrimPrefix(p, layerModuleRoot), "/")
			to := layerName(toRel)
			if to == "" {
				unclassified[layerDisp(toRel)] = true
				continue
			}
			if layerRank[to] <= layerRank[from] {
				continue
			}
			key := layerDisp(dir) + " -> " + layerDisp(toRel)
			if layerExemptions[key] {
				hitExempt[key] = true
				continue
			}
			violations[fmt.Sprintf("%s (%s) imports %s (%s)", layerDisp(dir), from, layerDisp(toRel), to)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(unclassified) > 0 {
		t.Errorf("%d unclassified package(s) — add them to layerName():\n  %s",
			len(unclassified), strings.Join(layerSortedKeys(unclassified), "\n  "))
	}
	if len(violations) > 0 {
		t.Errorf("%d upward layer-boundary import(s) — fix the dependency direction or, only if "+
			"genuinely pre-existing, add to layerExemptions (which may only shrink):\n  %s",
			len(violations), strings.Join(layerSortedKeys(violations), "\n  "))
	}
	for key := range layerExemptions {
		if !hitExempt[key] {
			t.Errorf("stale layer exemption %q — the upward import is gone; remove it from layerExemptions", key)
		}
	}
}

func layerDisp(rel string) string {
	if rel == "" {
		return "."
	}
	return rel
}

func layerSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
