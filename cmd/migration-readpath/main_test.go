package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func runArgs(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	stdout, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := os.CreateTemp(t.TempDir(), "err")
	if err != nil {
		t.Fatal(err)
	}
	code := run(args, stdout, stderr)
	out, _ := os.ReadFile(stdout.Name())
	er, _ := os.ReadFile(stderr.Name())
	return code, string(out), string(er)
}

func TestExpectationValidation(t *testing.T) {
	if err := validate(expectations{}); err == nil {
		t.Fatal("empty expectations must be rejected")
	}
	if err := validate(expectations{Clients: []clientCase{{}}}); err == nil {
		t.Fatal("client case without id must be rejected")
	}
	many := expectations{}
	for i := 0; i < 201; i++ {
		many.Clients = append(many.Clients, clientCase{ID: "c"})
	}
	if err := validate(many); err == nil {
		t.Fatal("over-budget expectations must be rejected")
	}
	if err := validate(expectations{Clients: []clientCase{{ID: "a"}}}); err != nil {
		t.Fatalf("valid single client rejected: %v", err)
	}
}

func TestRefusesWithoutMigrationAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	dsn := write(t, dir, "dsn", "postgres://x@127.0.0.1:1/y\n")
	expect := write(t, dir, "expect.json", `{"clients":[{"id":"a"}]}`)
	code, out, errText := runArgs(t, "-dsn-file", dsn, "-expect", expect)
	if code != 2 || out != "" {
		t.Fatalf("must fail closed without the acknowledgement: code=%d out=%q", code, out)
	}
	if !strings.Contains(errText, "refusing") {
		t.Fatalf("refusal reason missing: %q", errText)
	}
}

func TestInvalidExpectationJsonIsRejected(t *testing.T) {
	dir := t.TempDir()
	dsn := write(t, dir, "dsn", "postgres://x@127.0.0.1:1/y\n")
	expect := write(t, dir, "expect.json", `{`)
	code, _, errText := runArgs(t, "-dsn-file", dsn, "-expect", expect, "-allow-idempotent-migrations")
	if code != 2 || !strings.Contains(errText, "invalid") {
		t.Fatalf("invalid json must fail closed: code=%d err=%q", code, errText)
	}
}

func TestExpectedUnreadableIsPartOfTheContract(t *testing.T) {
	// An expired historical session must be refused; the case shape carries that expectation
	// so a correct refusal is reported as a pass rather than silently dropped.
	body, err := json.Marshal(sessionCase{ID: "s", ExpectUnreadable: true})
	if err != nil || !strings.Contains(string(body), `"expect_unreadable":true`) {
		t.Fatalf("expectation flag must serialise: %s %v", body, err)
	}
	if err := validate(expectations{Sessions: []sessionCase{{ID: "s"}}}); err != nil {
		t.Fatalf("session case without the flag is valid: %v", err)
	}
}

func TestCountExpectationsStayInsideTheClosedTableSet(t *testing.T) {
	good := expectations{Clients: []clientCase{{ID: "c"}}, Counts: map[string]int{"audit_events": 3}}
	if err := validate(good); err != nil {
		t.Fatalf("closed-set table count rejected: %v", err)
	}
	unknown := expectations{Clients: []clientCase{{ID: "c"}}, Counts: map[string]int{"users;DROP TABLE users": 1}}
	if err := validate(unknown); err == nil {
		t.Fatal("arbitrary table name must be rejected before it reaches SQL")
	}
	negative := expectations{Clients: []clientCase{{ID: "c"}}, Counts: map[string]int{"users": -1}}
	if err := validate(negative); err == nil {
		t.Fatal("negative count must be rejected")
	}
}

func TestEqualSortedIgnoresOrderButNotContent(t *testing.T) {
	if !equalSorted([]string{"b", "a"}, []string{"a", "b"}) {
		t.Fatal("role code comparison must be order-insensitive")
	}
	if equalSorted([]string{"a"}, []string{"a", "b"}) || equalSorted([]string{"a"}, []string{"b"}) {
		t.Fatal("different role code sets must fail")
	}
}

func TestRoleAndMenuCasesRequireIdentity(t *testing.T) {
	if err := validate(expectations{Roles: []roleCase{{UserID: "u"}}}); err == nil {
		t.Fatal("role case without a client must be rejected")
	}
	if err := validate(expectations{Clients: []clientCase{{ID: "c"}}, Menus: []menuCase{}}); err != nil {
		t.Fatalf("a run may omit menu cases: %v", err)
	}
	if err := validate(expectations{Menus: []menuCase{{ClientID: "c", Items: 2}}}); err != nil {
		t.Fatalf("valid menu case rejected: %v", err)
	}
}

func TestCaseResultsAndDigestComparison(t *testing.T) {
	ok := []caseResult{{Kind: "clients", ID: "a", OK: true}, {Kind: "users", ID: "b", OK: true}}
	if !allOK(ok) {
		t.Fatal("all matching cases must pass")
	}
	bad := append([]caseResult{}, ok...)
	bad = append(bad, caseResult{Kind: "sessions", ID: "c"})
	if allOK(bad) {
		t.Fatal("an unreadable case must fail the run")
	}
	if mismatch(true, "x") != "" || mismatch(false, "x") != "x" {
		t.Fatal("mismatch detail must only appear on failure")
	}
	same := digest{Rows: 10, Sum: "abc"}
	if same != (digest{Rows: 10, Sum: "abc"}) {
		t.Fatal("identical digests must compare equal")
	}
	body, err := json.Marshal(report{Result: "passed", Cases: ok, ExistingRowsUnchanged: true, MigrationsRun: true})
	if err != nil || !strings.Contains(string(body), `"existing_rows_unchanged":true`) {
		t.Fatalf("report must state the digest guarantee: %s %v", body, err)
	}
	_ = bytes.MinRead
}
