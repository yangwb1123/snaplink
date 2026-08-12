package legacysync

// Tenant-binding gate coverage: a mapped target client with an empty
// tenant binding fails the plan in both modes (REQ-2), the success path
// stays byte-identical (REQ-3 / T-9), and the failure-mode matrix rows
// 6-9 from the design are pinned here.

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
)

// seedClientRow inserts one clients row with the given tenant binding; a
// nil binding writes SQL NULL (only legal on the nullable schema variant).
func seedClientRow(t *testing.T, db *sql.DB, id string, active int, tenantID any) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO clients(id,active,tenant_id) VALUES (?,?,?)`, id, active, tenantID); err != nil {
		t.Fatalf("seed client %s: %v", id, err)
	}
}

// U1: an unbound mapped client (”) fails the plan in both modes, naming
// the client id and the tenant_id cause.
func TestBuildReportUnboundMappedClientFailsBothModes(t *testing.T) {
	t.Parallel()
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}}}
	target := targetSnapshot{Clients: map[string]string{"web": ""}}
	for _, mode := range []string{"dry-run", "applied"} {
		_, err := buildReport(plan, target, mode)
		if err == nil {
			t.Fatalf("mode %s: buildReport succeeded, want tenant-binding error", mode)
		}
		if !strings.Contains(err.Error(), `"web"`) || !strings.Contains(err.Error(), "tenant_id") {
			t.Fatalf("mode %s: error %q does not name client web / tenant_id", mode, err)
		}
	}
}

// U2: a bound mapped client passes in both modes.
func TestBuildReportBoundMappedClientSucceedsBothModes(t *testing.T) {
	t.Parallel()
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}}}
	target := targetSnapshot{Clients: map[string]string{"web": "tenant-acme"}}
	for _, mode := range []string{"dry-run", "applied"} {
		if _, err := buildReport(plan, target, mode); err != nil {
			t.Fatalf("mode %s: buildReport: %v", mode, err)
		}
	}
}

// U3: every unbound mapped client is named, one per line, in sorted order.
func TestBuildReportNamesEveryUnboundMappedClient(t *testing.T) {
	t.Parallel()
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}, "api": {}, "bound": {}}}
	target := targetSnapshot{Clients: map[string]string{"web": "", "api": "", "bound": "tenant-acme"}}
	_, err := buildReport(plan, target, "dry-run")
	if err == nil {
		t.Fatal("buildReport succeeded, want tenant-binding errors")
	}
	text := err.Error()
	if got := strings.Count(text, "has no tenant binding"); got != 2 {
		t.Fatalf("want exactly two per-client lines, got %d in %q", got, text)
	}
	for _, id := range []string{`"api"`, `"web"`} {
		if !strings.Contains(text, id) {
			t.Fatalf("error does not name %s: %q", id, text)
		}
	}
	if strings.Index(text, `"api"`) > strings.Index(text, `"web"`) {
		t.Fatalf("unbound clients not in sorted order: %q", text)
	}
}

// U4: a SQL NULL binding (nullable fixture) fails identically to ” —
// COALESCE collapses it before the gate sees it.
func TestBuildReportNullBindingTreatedAsUnbound(t *testing.T) {
	t.Parallel()
	db := openTestTargetWithSchema(t, testTargetSchemaNullableClients)
	seedClientRow(t, db, "web", 1, nil)
	target := targetSnapshot{Clients: map[string]string{}}
	if err := loadTargetClients(context.Background(), db, &target); err != nil {
		t.Fatalf("loadTargetClients: %v", err)
	}
	if got := target.Clients["web"]; got != "" {
		t.Fatalf("NULL binding = %q, want \"\" (COALESCE)", got)
	}
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}}}
	_, err := buildReport(plan, target, "dry-run")
	if err == nil || !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("want tenant-binding error for NULL binding, got %v", err)
	}
}

// M6: a mapped client absent from the snapshot (missing or inactive) keeps
// the pre-existing existence error, text unchanged.
func TestBuildReportMissingMappedClientKeepsExistenceError(t *testing.T) {
	t.Parallel()
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}}}
	target := targetSnapshot{Clients: map[string]string{}}
	_, err := buildReport(plan, target, "dry-run")
	if err == nil || !strings.Contains(err.Error(), "does not exist or is inactive") {
		t.Fatalf("want existence error, got %v", err)
	}
}

// M7: an unbound client outside the app map is out of the sync's managed
// scope and must not block the plan.
func TestBuildReportUnmappedUnboundClientPasses(t *testing.T) {
	t.Parallel()
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}}}
	target := targetSnapshot{Clients: map[string]string{"web": "tenant-acme", "other": ""}}
	if _, err := buildReport(plan, target, "dry-run"); err != nil {
		t.Fatalf("buildReport: %v", err)
	}
}

// M8: an empty app map leaves the gate loop a no-op.
func TestBuildReportEmptyAppMapPasses(t *testing.T) {
	t.Parallel()
	_, err := buildReport(syncPlan{}, targetSnapshot{Clients: map[string]string{}}, "dry-run")
	if err != nil {
		t.Fatalf("buildReport: %v", err)
	}
}

// M9: a whitespace binding counts as bound — exact-match semantics, no
// trimming (the server compares the column value literally).
func TestBuildReportWhitespaceBindingCountsAsBound(t *testing.T) {
	t.Parallel()
	plan := syncPlan{MappedClients: map[string]struct{}{"web": {}}}
	target := targetSnapshot{Clients: map[string]string{"web": " "}}
	if _, err := buildReport(plan, target, "dry-run"); err != nil {
		t.Fatalf("buildReport: %v", err)
	}
}

// U6: loadTargetClients carries the binding per active client — bound
// value, ” and SQL NULL both read as unbound.
func TestLoadTargetClientsCarriesTenantBinding(t *testing.T) {
	t.Parallel()
	db := openTestTargetWithSchema(t, testTargetSchemaNullableClients)
	seedClientRow(t, db, "bound", 1, "tenant-acme")
	seedClientRow(t, db, "empty", 1, "")
	seedClientRow(t, db, "null", 1, nil)
	target := targetSnapshot{Clients: map[string]string{}}
	if err := loadTargetClients(context.Background(), db, &target); err != nil {
		t.Fatalf("loadTargetClients: %v", err)
	}
	want := map[string]string{"bound": "tenant-acme", "empty": "", "null": ""}
	for id, tenant := range want {
		if got := target.Clients[id]; got != tenant {
			t.Fatalf("client %s tenant = %q, want %q", id, got, tenant)
		}
	}
}

// U7: a clients table without the tenant_id column fails loudly with a SQL
// error (every server-created target has the column via the v1 migration).
func TestLoadTargetClientsMissingTenantColumnFailsLoudly(t *testing.T) {
	t.Parallel()
	db := openTestTargetWithSchema(t, testTargetSchemaNoTenantColumn)
	if _, err := db.Exec(`INSERT INTO clients(id,active) VALUES ('web',1)`); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	err := loadTargetClients(context.Background(), db, &targetSnapshot{Clients: map[string]string{}})
	if err == nil {
		t.Fatal("loadTargetClients succeeded on a clients table without tenant_id")
	}
	if !strings.Contains(err.Error(), "tenant_id") {
		t.Fatalf("want a SQL error naming tenant_id, got %v", err)
	}
}

// U5: printReport stays byte-identical to the three-line format — the
// per-client diagnostic appears only in the failure stderr, never here.
func TestPrintReportGolden(t *testing.T) {
	t.Parallel()
	report := syncReport{
		Source:          sourceSummary{Users: 10, Active: 8, Inactive: 2, Roles: 5, Grants: 7, Overrides: 1},
		CreateUsers:     3,
		UpdateUsers:     2,
		DeactivateUsers: 1,
		Credentials:     3,
		Roles:           5,
		Assignments:     6,
	}
	for _, mode := range []string{"dry-run", "applied"} {
		report.Mode = mode
		var buf bytes.Buffer
		printReport(&buf, report)
		want := "legacy-sync mode=" + mode + "\n" +
			"source users=10 active=8 inactive=2 roles=5 grants=7 overrides=1\n" +
			"target create_users=3 update_users=2 deactivate_users=1 credentials=3 roles=5 assignments=6\n"
		if buf.String() != want {
			t.Fatalf("mode %s: report = %q, want %q", mode, buf.String(), want)
		}
	}
}
