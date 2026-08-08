package generate

// Contract assertions for generated scaffold output (R2–R5 of the
// verify-gate requirements). Each assertion is separately named so a
// template regression fails with the exact violated invariant, and they run
// on the generated artifact (which embeds the template's comment text
// verbatim), not on the template source: a regression in teaching content
// is a regression in what operators receive.

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// generatedFile resolves the file Generate produces for a kind+name pair,
// mirroring the filename rules in generate.go (%s.go, %s_store.go,
// %s_handler.go, %s_grant.go).
func generatedFile(kind, name, outputDir string) string {
	var suffix string
	switch kind {
	case "store":
		suffix = "_store.go"
	case "handler":
		suffix = "_handler.go"
	case "grant":
		suffix = "_grant.go"
	default:
		suffix = ".go"
	}
	return filepath.Join(outputDir, name+suffix)
}

var docRowRE = regexp.MustCompile("(?m)^\\| `([a-z_][a-z0-9_]*)`")

// registeredSet parses docs/error-codes.md into the set of registered wire
// codes (first-column backticked rows). The >= 200-row parse floor guards
// against doc-format drift silently emptying the registry the assertions
// check against (rows, not distinct codes — codes legitimately repeat
// across sections).
func registeredSet(t *testing.T, root string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "docs", "error-codes.md"))
	if err != nil {
		t.Fatalf("read docs/error-codes.md: %v", err)
	}
	rows := 0
	set := map[string]bool{}
	for _, m := range docRowRE.FindAllSubmatch(data, -1) {
		set[string(m[1])] = true
		rows++
	}
	if rows < 200 {
		t.Fatalf("docs/error-codes.md registered-code parse floor violated: expected >= 200 rows, extracted %d (doc format drift?)", rows)
	}
	return set
}

var errConstRE = regexp.MustCompile(`(?m)^\s*Err([A-Za-z0-9_]+)\s*=\s*"([a-z_][a-z0-9_]*)"`)

// resolveErrCode parses shared/core/errors.go's ErrX = "code" declarations
// into a symbol -> wire-code map, so constant-form ErrorBody(core.ErrX)
// occurrences in generated output can be resolved to their codes.
func resolveErrCode(t *testing.T, root string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "shared", "core", "errors.go"))
	if err != nil {
		t.Fatalf("read shared/core/errors.go: %v", err)
	}
	codes := map[string]string{}
	for _, m := range errConstRE.FindAllSubmatch(data, -1) {
		codes["Err"+string(m[1])] = string(m[2])
	}
	return codes
}

var pathDeclRE = regexp.MustCompile(`(?m)^\s*(Path[A-Za-z0-9_]+)\s*=`)

// pathConsts parses the Path* constant block in shared/core/consts.go, the
// only sanctioned source of endpoint paths in generated output.
func pathConsts(t *testing.T, root string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "shared", "core", "consts.go"))
	if err != nil {
		t.Fatalf("read shared/core/consts.go: %v", err)
	}
	set := map[string]bool{}
	for _, m := range pathDeclRE.FindAllSubmatch(data, -1) {
		set[string(m[1])] = true
	}
	return set
}

var errorBodyRE = regexp.MustCompile(`ErrorBody\(\s*("([^"]*)"|core\.(Err[A-Za-z0-9_]+))\s*\)`)

// assertRegisteredErrorCodes (R2) fails when generated output — code or
// comment — emits an ErrorBody code outside the docs/error-codes.md
// registered set. Raw-string codes resolve through the doc set; constant
// forms resolve through shared/core/errors.go first.
func assertRegisteredErrorCodes(t *testing.T, kind string, content []byte, root string) {
	t.Helper()
	registered := registeredSet(t, root)
	consts := resolveErrCode(t, root)

	for _, m := range errorBodyRE.FindAllSubmatch(content, -1) {
		var code string
		if raw := m[2]; len(raw) > 0 {
			code = string(raw)
		} else {
			// Group 3 already includes the Err prefix (core.ErrX).
			sym := string(m[3])
			var ok bool
			if code, ok = consts[sym]; !ok {
				t.Errorf("%s scaffold: ErrorBody references core.%s, which is not declared in shared/core/errors.go", kind, m[3])
				continue
			}
		}
		if !registered[code] {
			t.Errorf("%s scaffold: ErrorBody code %q is not registered in docs/error-codes.md", kind, code)
		}
	}
}

var urlWithPortRE = regexp.MustCompile(`https?://[^"/]*:[0-9]+`)
var hostPortPortRE = regexp.MustCompile(`[A-Za-z0-9.-]+:[0-9]+:[0-9]+`)

// assertNoLegacyPathPort (R3.1/R3.2) bans the legacy discovery defect
// shapes: the /authenticate login path and explicit numeric ports (8080,
// the unparseable host:8080:0 double-colon form, or any quoted URL with a
// numeric port).
func assertNoLegacyPathPort(t *testing.T, kind string, content []byte) {
	t.Helper()
	if bytes.Contains(content, []byte("/authenticate")) {
		t.Errorf("%s scaffold: legacy login path /authenticate — the modern route is core.PathLogin", kind)
	}
	if bytes.Contains(content, []byte("8080")) {
		t.Errorf("%s scaffold: literal port 8080 — legacy discovery defect shape; no numeric ports in generated output", kind)
	}
	if m := urlWithPortRE.Find(content); m != nil {
		t.Errorf("%s scaffold: URL with explicit numeric port %q — legacy defect shape", kind, m)
	}
	if m := hostPortPortRE.Find(content); m != nil {
		t.Errorf("%s scaffold: host:port:port double-colon shape %q — legacy 8080:0 defect shape", kind, m)
	}
}

var pathLiteralRE = regexp.MustCompile(`"\/[^"]*"`)
var pathRefRE = regexp.MustCompile(`core\.(Path[A-Za-z0-9_]+)`)

// assertNoPathLiterals (R3.3) bans inline slash-prefixed path literals and
// requires every core.Path* reference to exist in shared/core/consts.go.
func assertNoPathLiterals(t *testing.T, kind string, content []byte, root string) {
	t.Helper()
	if m := pathLiteralRE.Find(content); m != nil {
		t.Errorf("%s scaffold: inline slash-prefixed path literal %q — route paths must be core.Path* constants from shared/core/consts.go", kind, m)
	}
	consts := pathConsts(t, root)
	for _, m := range pathRefRE.FindAllSubmatch(content, -1) {
		sym := string(m[1])
		if !consts[sym] {
			t.Errorf("%s scaffold: references core.%s, which is not declared in shared/core/consts.go", kind, sym)
		}
	}
}

// assertFormContentTypeGuard (R4, handler kind only) requires the POST path
// to teach the form-urlencoded Content-Type guard (media-type literal +
// header check) positioned before any ctx.Bind( occurrence, mirroring the
// B4-4 server posture (interfaces/sso/server_login_resolve.go precedent).
func assertFormContentTypeGuard(t *testing.T, kind string, content []byte) {
	t.Helper()
	text := string(content)
	mediaIdx := strings.Index(text, "application/x-www-form-urlencoded")
	ctIdx := strings.Index(text, `Header.Get("Content-Type")`)
	bindIdx := strings.Index(text, "ctx.Bind(")
	if bindIdx < 0 {
		t.Errorf("%s scaffold: no ctx.Bind( in the generated handler — the POST binding example was dropped", kind)
		return
	}
	if mediaIdx < 0 {
		t.Errorf("%s scaffold: missing application/x-www-form-urlencoded media-type literal in the POST path", kind)
	}
	if ctIdx < 0 {
		t.Errorf("%s scaffold: missing Content-Type header check in the POST path", kind)
	}
	if mediaIdx >= 0 && ctIdx >= 0 && (mediaIdx > bindIdx || ctIdx > bindIdx) {
		t.Errorf("%s scaffold: the form-urlencoded Content-Type guard must precede ctx.Bind( (media at %d, header check at %d, bind at %d)", kind, mediaIdx, ctIdx, bindIdx)
	}
}

var rolesClaimRE = regexp.MustCompile(`Roles:\s+roles`)

// assertGrantScopeGateClaims (grant kind only) pins the B4-2 per-client
// scope gate and the B4-1 claim sources in the generated grant scaffold:
// the allowlist branch (GrantedScopes/SplitScope/invalid_scope), the roles
// source, and the tenant binding must all appear textually before
// issuance, and issuance must hand Issue the validated grantedScopes set —
// never the raw request-scope tail (}, scopes)). Each marker is asserted
// separately so a regression names the exact invariant dropped/reordered.
// Note: grantedScopes) is the Issue-call argument tail, so it is checked
// for presence only; the before-issuance ordering applies to the branch
// and roles markers. The roles ordering marker is h.Roles( — the example
// call, not the permissions.Provider.Roles citation — and the Subject
// projection is pinned separately via Roles:\s+roles (gofmt aligns the
// struct literal, so a plain contains check would false-positive).
func assertGrantScopeGateClaims(t *testing.T, kind string, content []byte) {
	t.Helper()
	text := string(content)
	issueIdx := strings.Index(text, "issuer.Issue(")
	if issueIdx < 0 {
		t.Errorf("%s scaffold: no issuer.Issue( in the generated grant — the issuance example was dropped", kind)
		return
	}
	for _, m := range []struct{ name, marker string }{
		{"per-client scope gate", "GrantedScopes("},
		{"scope split", "SplitScope("},
		{"invalid_scope error", "core.ErrInvalidScope"},
		{"roles source", "h.Roles("},
	} {
		idx := strings.Index(text, m.marker)
		if idx < 0 {
			t.Errorf("%s scaffold: missing %s marker %q — the B4-2/B4-1 teaching was dropped", kind, m.name, m.marker)
			continue
		}
		if idx > issueIdx {
			t.Errorf("%s scaffold: %s marker %q at %d must precede issuer.Issue( at %d — ordering regressed", kind, m.name, m.marker, idx, issueIdx)
		}
	}
	if !strings.Contains(text, "grantedScopes)") {
		t.Errorf("%s scaffold: issuance does not pass the validated grantedScopes set — raw request scopes would bypass the per-client gate", kind)
	}
	if strings.Contains(text, "}, scopes)") {
		t.Errorf("%s scaffold: issuance passes raw request scopes (}, scopes)) — the B4-2 bypass pattern is back", kind)
	}
	if !strings.Contains(text, "TenantID: client.TenantID") {
		t.Errorf("%s scaffold: tenant binding TenantID: client.TenantID missing from the Subject literal", kind)
	}
	if !rolesClaimRE.MatchString(text) {
		t.Errorf("%s scaffold: the Subject literal does not project the resolved roles (Roles: roles) — the B4-1 roles handoff was dropped", kind)
	}
}

// assertKindInvariants dispatches the kind-specific contract assertions on
// the generated artifact. Handler scaffolds must teach the form-urlencoded
// Content-Type guard before binding; grant scaffolds must teach the
// per-client scope gate and the B4-1 claim sources (B4-2/B4-1).
func assertKindInvariants(t *testing.T, kind string, content []byte) {
	t.Helper()
	switch kind {
	case "handler":
		assertFormContentTypeGuard(t, kind, content)
	case "grant":
		assertGrantScopeGateClaims(t, kind, content)
	}
}

// TestVerifyGeneratedBuildVet proves the generation-time gate runs `go vet`
// in addition to `go build`: a package that compiles but fails vet must be
// rejected with a vet-naming error. The test chdirs into the buildable
// module it verifies because go build/vet on an absolute directory outside
// the current module is a pre-existing "outside main module" quirk.
func TestVerifyGeneratedBuildVet(t *testing.T) {
	root := repoRoot(t)
	dir := t.TempDir()
	newBuildableModule(t, dir, root)

	pkgDir := filepath.Join(dir, "gen", "vettest")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(src), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	write("clean.go", "package vettest\n\n// Clean builds and vets clean.\nfunc Clean() int { return 1 }\n")
	if err := verifyGeneratedBuild("gen/vettest"); err != nil {
		t.Fatalf("clean package rejected: %v", err)
	}

	write("bad.go", "package vettest\n\nimport \"fmt\"\n\n// Bad compiles but fails vet: Printf format/arg type mismatch.\nfunc Bad() {\n\tfmt.Printf(\"%d\", \"not a number\")\n}\n")
	err = verifyGeneratedBuild("gen/vettest")
	if err == nil {
		t.Fatal("vet-violating package accepted: verifyGeneratedBuild must run go vet")
	}
	if !strings.Contains(err.Error(), "go vet") {
		t.Fatalf("vet failure not attributed to go vet: %v", err)
	}
}

// TestRunExitCodes locks the CLI's exit-code contract (T-9): unknown kind
// and missing --name/--package are usage errors (2), a failed
// generation-time build check exits 1, --skip-build-check succeeds (0)
// without running build or vet, and the full gate exits 0 inside a
// buildable module.
func TestRunExitCodes(t *testing.T) {
	if got := Run([]string{"bogus"}); got != 2 {
		t.Errorf("unknown kind: exit = %d, want 2", got)
	}
	if got := Run([]string{"handler", "--package", "internal/handler"}); got != 2 {
		t.Errorf("missing --name: exit = %d, want 2", got)
	}
	if got := Run([]string{"handler", "--name", "webhook"}); got != 2 {
		t.Errorf("missing --package: exit = %d, want 2", got)
	}

	skipDir := t.TempDir()
	if got := Run([]string{"handler", "--name", "webhook", "--package", "internal/handler", "--output", skipDir, "--skip-build-check"}); got != 0 {
		t.Errorf("--skip-build-check: exit = %d, want 0", got)
	}
	if _, err := os.Stat(filepath.Join(skipDir, "webhook_handler.go")); err != nil {
		t.Errorf("--skip-build-check did not generate the handler file: %v", err)
	}

	// Output dir outside any Go module: go build fails ("outside main
	// module") and the caller must exit 1.
	failDir := t.TempDir()
	if got := Run([]string{"handler", "--name", "webhook", "--package", "internal/handler", "--output", failDir}); got != 1 {
		t.Errorf("build-check failure: exit = %d, want 1", got)
	}

	// Full gate inside a buildable module: absolute --output, chdir'd so the
	// module context resolves; build AND vet both run and pass (exit 0).
	modDir := t.TempDir()
	newBuildableModule(t, modDir, repoRoot(t))
	genDir := filepath.Join(modDir, "gen", "internal", "handler")
	if err := os.MkdirAll(genDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(modDir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	if got := Run([]string{"handler", "--name", "webhook", "--package", "internal/handler", "--output", genDir}); got != 0 {
		t.Errorf("in-module generate with build+vet check: exit = %d, want 0", got)
	}
}
