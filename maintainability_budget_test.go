package sso

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Harness gate (Harness Engineering): a per-file maintainability budget enforced
// as a committed test, so it runs inside the existing `go test` / `make ci` gate
// without depending on the generative `make harness` stack. Files much larger
// than this are disproportionately expensive for humans AND long-running AI
// agents to hold in context, and reliably accrete into god-files (this gate
// exists because a session grew handlers.go to 4405 lines unnoticed — the
// committed golangci gate only measures per-FUNCTION complexity, not per-FILE
// size).
//
// Ratchet semantics:
//   - A NEW (non-exempt) production .go file over the budget FAILS — split it
//     into focused files instead (see handlers_admin.go / handlers_b2b.go).
//   - The files already over budget are listed in fileSizeExemptions. You may
//     NOT add to that list. Once an exempt file is refactored back under budget
//     it must be removed (the test flags stale exemptions), so the backlog only
//     ever shrinks.
//
// Scope: parent-module, non-generated, non-test .go files. Nested modules
// (kms/ redis/ saml/ …) have their own go.mod and are out of scope here; test
// files are excluded (table-driven tests legitimately run long).
const maxFileLines = 500

// fileSizeExemptions is the frozen backlog of files that exceeded maxFileLines
// when this gate was introduced. SHRINK THIS LIST; never grow it.
var fileSizeExemptions = map[string]bool{
	"accessors.go":                         true,
	"anomaly/runner.go":                    true,
	"audit/recorder_events.go":             true,
	"audit/sqlite/sink.go":                 true,
	"authenticators/webauthn/webauthn.go":  true,
	"caep/receiver.go":                     true,
	"cmd/sso-import/main.go":               true,
	"cmd/sso-server/main.go":               true,
	"cmd/sso-server/build_stores.go":            true,
	"config/config.go":                     true,
	"core/consts.go":                       true,
	"core/types.go":                        true,
	"defaultimpl/ecdsa_jwt_issuer.go":      true,
	"defaultimpl/ed25519_jwt_issuer.go":    true,
	"defaultimpl/push_mfa_provider.go":     true,
	"defaultimpl/rsa_jwt_issuer.go":        true,
	"defaultimpl/sqlite/clients.go":        true,
	"defaultimpl/sqlite/refresh_tokens.go": true,
	"defaultimpl/vaulttransit/signer.go":   true,
	"federation/entity_statement.go":       true,
	"federation/metadata_policy.go":        true,
	"federation/registration.go":           true,
	"federation/trust_chain.go":            true,
	"federation/trust_marks.go":            true,
	"metrics/metrics.go":                   true,
	"permissions/sqlite/sqlite.go":         true,
	"scim/handler.go":                      true,
	"signing_key_aggregation.go":           true,
	"signingkeys/etcd/etcd.go":             true,
	"snapshot/restorer.go":                 true,
	"sso.go":                               true,
	"tenant/sqlite/sqlite.go":              true,
}

// skipDirs are not part of this module's hand-written production surface.
var skipDirs = map[string]bool{
	"gen": true, ".claude": true, ".git": true, "web": true, "node_modules": true,
	"dist": true, "bin": true,
	// nested modules (own go.mod)
	"kms": true, "redis": true, "saml": true, "ldap": true,
	"extauthz": true, "kerberos": true, "radius": true,
}

func TestMaintainability_FileSizeBudget(t *testing.T) {
	var overBudget, staleExemptions []string
	seenExempt := map[string]bool{}

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
		n, lerr := countFileLines(path)
		if lerr != nil {
			return lerr
		}
		exempt := fileSizeExemptions[rel]
		if exempt {
			seenExempt[rel] = true
			if n <= maxFileLines {
				staleExemptions = append(staleExemptions, fmt.Sprintf("%s (%d lines — now under budget)", rel, n))
			}
			return nil
		}
		if n > maxFileLines {
			overBudget = append(overBudget, fmt.Sprintf("%s (%d lines)", rel, n))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(overBudget) > 0 {
		sort.Strings(overBudget)
		t.Errorf("%d file(s) exceed the %d-line maintainability budget — split into focused "+
			"files (e.g. handlers_<domain>.go) instead of growing a god-file:\n  %s",
			len(overBudget), maxFileLines, strings.Join(overBudget, "\n  "))
	}
	if len(staleExemptions) > 0 {
		sort.Strings(staleExemptions)
		t.Errorf("%d exemption(s) no longer needed — remove them from fileSizeExemptions (the "+
			"backlog must only shrink):\n  %s", len(staleExemptions), strings.Join(staleExemptions, "\n  "))
	}
	// A listed exemption whose file vanished (renamed/deleted) is also stale.
	for rel := range fileSizeExemptions {
		if !seenExempt[rel] {
			if _, statErr := os.Stat(rel); statErr != nil {
				t.Errorf("exemption for missing file %q — remove it from fileSizeExemptions", rel)
			}
		}
	}
}

func countFileLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++ // final line without trailing newline
	}
	return n, nil
}
