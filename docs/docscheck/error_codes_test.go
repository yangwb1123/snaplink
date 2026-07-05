package docscheck

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestErrorCodesDocumented is the "error-code -> consts" drift checker from
// docs/deferred-backlog.md. docs/error-codes.md documents the wire-format
// strings the server puts in the `"error"` JSON field; those are declared in
// Go as exported `Err<CamelCase> = "snake_case"` constants (shared/core/errors.go
// plus a handful of per-handler files — see error-codes.md's own "Defined as
// Go constants in consts.go (and in the per-handler files ...)" note). This
// cross-references the two directions:
//
//   - every docs/error-codes.md "Code"-table entry has a matching Go Err*
//     constant with that exact string value, OR is in docCodeExceptions
//     (below) — a SMALL, named, commented list of codes the docs themselves
//     already explain are deliberately NOT core.Err*-backed;
//   - every Go Err* wire-string constant has a matching docs/error-codes.md
//     entry.
//
// docs/error-codes.md also has two smaller "Sentinel" tables (SDK Go errors,
// not wire codes — see TestSentinelErrorsDocumented) and one "`scimType`"
// table (a genuinely separate RFC 7644 taxonomy, explicitly called out in the
// doc's own prose as "a SEPARATE taxonomy from the OAuth error catalog
// above"); both are skipped here by construction, since scanDocCodeTable
// only reads tables headed exactly "Code".
func TestErrorCodesDocumented(t *testing.T) {
	goCodes := scanGoWireCodes(t)
	docCodes, err := scanDocCodeTable(filepath.Join(repoRoot, "docs/error-codes.md"))
	if err != nil {
		t.Fatalf("parse docs/error-codes.md: %v", err)
	}
	if len(docCodes) < 50 || len(goCodes) < 50 {
		t.Fatalf("sanity floor tripped: found %d doc codes / %d go codes — a parser regression "+
			"would otherwise make this test vacuously pass", len(docCodes), len(goCodes))
	}

	var docNotGo []string
	for code := range docCodes {
		if _, ok := goCodes[code]; ok {
			continue
		}
		if docCodeExceptions[code] {
			continue
		}
		docNotGo = append(docNotGo, code)
	}
	sort.Strings(docNotGo)
	if len(docNotGo) > 0 {
		t.Errorf("%d docs/error-codes.md code(s) have no matching `Err<Name> = \"<code>\"` Go constant "+
			"anywhere in the repo (and are not in docCodeExceptions): %s",
			len(docNotGo), strings.Join(docNotGo, ", "))
	}

	var goNotDoc []string
	for code, ids := range goCodes {
		if docCodes[code] {
			continue
		}
		goNotDoc = append(goNotDoc, fmt.Sprintf("%s (%s)", code, strings.Join(ids, ", ")))
	}
	sort.Strings(goNotDoc)
	if len(goNotDoc) > 0 {
		t.Errorf("%d Go Err* wire-code constant(s) have no docs/error-codes.md entry — add a row to the "+
			"relevant \"Code\" table in the same commit (AGENTS.md: \"New Err* -> update docs/error-codes.md\"): %s",
			len(goNotDoc), strings.Join(goNotDoc, ", "))
	}
}

// docCodeExceptions are docs/error-codes.md codes the doc's OWN prose already
// explains are intentionally NOT core.Err*-backed — implemented as unexported
// local literals instead (a different naming convention: `err...`/`code...`,
// never exported `Err...`). Grep-verified against the current source; this
// list may only ever explain an EXISTING, deliberate exception, never
// silence a newly-introduced one (a new code should get an Err* constant
// like every other one, not grow this list).
var docCodeExceptions = map[string]bool{
	// "All are local literals (not core.Err*)" — docs/error-codes.md's own
	// "Transport-level checks" section. Backed by interfaces/admin/governance.go's
	// unexported errAdminWriteQuotaExceeded / errAdminIPDenied / errDestructiveConfirmRequired.
	"admin_ip_denied":                   true,
	"destructive_confirmation_required": true,
	"admin_write_quota_exceeded":        true,
	// cmd/sso-server/serverwebauthn/webauthn_handlers.go's codeAttestationDenied
	// — composition-layer (cmd) glue, not an SDK core.Err* wire constant.
	"attestation_denied": true,
	// cmd/sso-server/serverwebauthn/webauthn.go returns this as a plain string
	// literal from a ceremony-outcome mapping helper, same composition-layer reason.
	"ceremony_failed": true,
}

// wireConstRe matches an exported Err<Name> string-literal constant, in
// EITHER a const-block member form (`ErrX = "y"`) or a standalone form
// (`const ErrX = "y"`) — both are used across the repo.
var wireConstRe = regexp.MustCompile(`^\s*(?:const\s+)?(Err[A-Za-z0-9]+)\s*=\s*"([a-zA-Z0-9_]+)"\s*(?://.*)?$`)

// scanGoWireCodes finds every exported `Err<Name> = "<code>"` constant in the
// repo, returning code -> the identifier(s)/file(s) that define it (a code
// can legitimately have more than one identifier, e.g. ErrInvalidRequest and
// ErrFederationInvalidRequest both equal "invalid_request").
//
// This is a line-level regex scan rather than a go/ast scan (unlike the
// route/config checkers) because the distinguishing signal here — "string
// literal RHS, not errors.New(...)" — is trivial to express as a line
// pattern, and the exported-Err*-with-string-value shape never spans
// multiple lines in this codebase.
func scanGoWireCodes(t *testing.T) map[string][]string {
	codes := map[string][]string{}
	err := walkGoFiles(repoRoot, func(path string) {
		f, oerr := os.Open(path)
		if oerr != nil {
			t.Errorf("open %s: %v", path, oerr)
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			m := wireConstRe.FindStringSubmatch(sc.Text())
			if m == nil {
				continue
			}
			rel, _ := filepath.Rel(repoRoot, path)
			codes[m[2]] = append(codes[m[2]], m[1]+" ("+filepath.ToSlash(rel)+")")
		}
	})
	if err != nil {
		t.Fatalf("walk %s: %v", repoRoot, err)
	}
	return codes
}

// ---- docs/error-codes.md table parsing (shared with the Sentinel check) ----

// tableFirstColRe pulls a single backtick-quoted token out of a table row's
// first column.
var tableFirstColRe = regexp.MustCompile("^\\|\\s*`([a-zA-Z0-9_]+)`")

// headerFirstColRe pulls the (possibly backtick-quoted) label out of a table
// HEADER row's first column, so callers can select tables by header text
// ("Code" vs "Sentinel" vs "`scimType`" vs "Endpoint").
var headerFirstColRe = regexp.MustCompile(`^\|\s*([^|]*?)\s*\|`)

var tableSeparatorRe = regexp.MustCompile(`^\|[-| ]+\|$`)

// scanDocCodeTable extracts every first-column backtick token from every
// markdown table in file whose header's first cell is exactly "Code" —
// docs/error-codes.md's convention for a wire-format-code table (as opposed
// to its "Sentinel", "`scimType`", or "Endpoint" tables, which use the same
// pipe-table syntax for a different purpose and are deliberately NOT
// included here).
func scanDocCodeTable(file string) (map[string]bool, error) {
	return scanDocTableByHeader(file, "Code")
}

// scanDocTableByHeader is the shared table-selection primitive: a markdown
// table "belongs" to this checker when the line immediately above its
// `|---|---|` separator has headerLabel as its (trimmed) first column.
func scanDocTableByHeader(file, headerLabel string) (map[string]bool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	out := map[string]bool{}
	inTable := false
	for i, line := range lines {
		if tableSeparatorRe.MatchString(line) && i > 0 {
			h := headerFirstColRe.FindStringSubmatch(lines[i-1])
			inTable = h != nil && strings.Trim(strings.TrimSpace(h[1]), "`") == headerLabel
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		if m := tableFirstColRe.FindStringSubmatch(line); m != nil {
			out[m[1]] = true
		}
	}
	return out, nil
}

// sentinelTableDirs are the Go packages docs/error-codes.md's "Sentinel"-
// headed tables document (each self-describes as "SDK Go errors, not HTTP
// wire codes" — a caller branches on them with errors.Is, so the doc lists
// the Go IDENTIFIER itself, not a derived wire string):
// interfaces/ssoclient/rs (resource-server token validation),
// shared/security/securityverify (outbound webhook signature verification),
// and platform/audit/auditexport (bulk audit-export bundle build/verify).
// Identifiers are matched against the UNION of all dirs rather than
// per-table (the tables don't share any identifier names in practice, so
// this is simpler than threading a table->dir association through
// scanDocTableByHeader for no extra safety).
var sentinelTableDirs = []string{"interfaces/ssoclient/rs", "shared/security/securityverify", "platform/audit/auditexport"}

// TestSentinelErrorsDocumented is a secondary, smaller check alongside
// TestErrorCodesDocumented: docs/error-codes.md's two "Sentinel"-headed
// tables list Go error IDENTIFIERS directly (not wire strings), so the
// correspondence is exact-identifier-match rather than the Code tables'
// value-match. Verifies every table entry names a real `Err<Name> =
// errors.New(...)` declared in its documented package.
func TestSentinelErrorsDocumented(t *testing.T) {
	sentinelIdents, err := scanDocTableByHeader(filepath.Join(repoRoot, "docs/error-codes.md"), "Sentinel")
	if err != nil {
		t.Fatalf("parse docs/error-codes.md: %v", err)
	}
	if len(sentinelIdents) < 10 {
		t.Fatalf("sanity floor tripped: found only %d Sentinel-table identifiers", len(sentinelIdents))
	}

	declared := map[string]bool{}
	for _, dir := range sentinelTableDirs {
		full := filepath.Join(repoRoot, dir)
		derr := walkGoFiles(full, func(path string) {
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Errorf("read %s: %v", path, rerr)
				return
			}
			for _, m := range sentinelDeclRe.FindAllStringSubmatch(string(data), -1) {
				declared[m[1]] = true
			}
		})
		if derr != nil {
			t.Fatalf("walk %s: %v", full, derr)
		}
	}

	var missing []string
	for ident := range sentinelIdents {
		if !declared[ident] {
			missing = append(missing, ident)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d docs/error-codes.md Sentinel-table identifier(s) have no matching "+
			"`Err<Name> = errors.New(...)` declaration in %v: %s",
			len(missing), sentinelTableDirs, strings.Join(missing, ", "))
	}
}

var sentinelDeclRe = regexp.MustCompile(`\b(Err[A-Za-z0-9]+)\s*=\s*errors\.New\(`)
