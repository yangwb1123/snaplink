package legacysync

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"
)

func TestApplyPlanPreservesNativeAuthorizationAndMenus(t *testing.T) {
	t.Parallel()
	db := openTestTarget(t)
	seedTarget(t, db)
	plan, err := buildPlan(legacyFixture(t), map[string]string{"ERP_WEB": "sverp-web"},
		map[string]string{"ERP_WEB:ROOT": "admin"}, nil)
	if err != nil {
		t.Fatalf("buildPlan: %v", err)
	}
	target, err := inspectTarget(context.Background(), db)
	if err != nil {
		t.Fatalf("inspectTarget: %v", err)
	}
	if _, err := buildReport(plan, target, "applied"); err != nil {
		t.Fatalf("buildReport: %v", err)
	}
	if err := applyPlan(context.Background(), db, plan, target); err != nil {
		t.Fatalf("applyPlan: %v", err)
	}
	assertAppliedUsers(t, db)
	assertAppliedAuthorization(t, db)
	assertMenuUnchanged(t, db)
}

func TestBuildReportRejectsNativeUserCollision(t *testing.T) {
	t.Parallel()
	plan := syncPlan{Users: []plannedUser{{ID: "native", ExternalID: "legacy-native"}}}
	target := targetSnapshot{
		Users:       map[string]targetUser{"native": {ID: "native", Provider: "password"}},
		ExternalIDs: map[string]string{}, Roles: map[string]struct{}{},
		Assignments: map[assignmentKey][]string{}, Clients: map[string]string{},
	}
	if _, err := buildReport(plan, target, "dry-run"); err == nil {
		t.Fatal("buildReport succeeded, want collision error")
	}
}

func openTestTarget(t *testing.T) *sql.DB {
	t.Helper()
	return openTestTargetWithSchema(t, testTargetSchema)
}

func openTestTargetWithSchema(t *testing.T, schema string) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "target.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	return db
}

func seedTarget(t *testing.T, db *sql.DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO clients(id,active,tenant_id) VALUES ('sverp-web',1,'tenant-acme')`,
		`INSERT INTO users(id,provider,attributes,created_at,updated_at)
         VALUES ('native','password','{}',1,1),('retired','sv_sso','{"scim:active":"true"}',1,1)`,
		`INSERT INTO permissions_roles(client_id,role_code,name,description,permissions_json)
         VALUES ('sverp-web','admin','Admin','','["content:read"]'),
                ('sverp-web','legacy:ERP_WEB:STALE','Stale','','[]')`,
		`INSERT INTO permissions_assignments(user_id,client_id,roles_json)
         VALUES ('native','sverp-web','["admin","legacy:ERP_WEB:STALE"]')`,
		`INSERT INTO permissions_menus(client_id,menu_json)
         VALUES ('sverp-web','[{"code":"content","required_permission":"content:read"}]')`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed target: %v", err)
		}
	}
}

func assertAppliedUsers(t *testing.T, db *sql.DB) {
	t.Helper()
	var provider, externalID, hash string
	if err := db.QueryRow(`SELECT u.provider,u.external_id,p.hash FROM users u
        JOIN password_credentials p ON p.user_id=u.id WHERE u.id='alice'`).Scan(&provider, &externalID, &hash); err != nil {
		t.Fatalf("query alice: %v", err)
	}
	if provider != legacyProvider || externalID != "uuid-alice" || hash == "" {
		t.Fatalf("alice provider=%q external_id=%q hash_empty=%t", provider, externalID, hash == "")
	}
	var raw string
	if err := db.QueryRow(`SELECT attributes FROM users WHERE id='retired'`).Scan(&raw); err != nil {
		t.Fatalf("query retired: %v", err)
	}
	var attrs map[string]string
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil || attrs[activeAttr] != "false" {
		t.Fatalf("retired attributes=%q err=%v", raw, err)
	}
}

func assertAppliedAuthorization(t *testing.T, db *sql.DB) {
	t.Helper()
	var nativeRaw, aliceRaw string
	if err := db.QueryRow(`SELECT roles_json FROM permissions_assignments
        WHERE user_id='native' AND client_id='sverp-web'`).Scan(&nativeRaw); err != nil {
		t.Fatalf("query native assignment: %v", err)
	}
	if err := db.QueryRow(`SELECT roles_json FROM permissions_assignments
        WHERE user_id='alice' AND client_id='sverp-web'`).Scan(&aliceRaw); err != nil {
		t.Fatalf("query alice assignment: %v", err)
	}
	var native, alice []string
	if err := json.Unmarshal([]byte(nativeRaw), &native); err != nil {
		t.Fatalf("decode native roles: %v", err)
	}
	if err := json.Unmarshal([]byte(aliceRaw), &alice); err != nil {
		t.Fatalf("decode alice roles: %v", err)
	}
	if !slices.Equal(native, []string{"admin"}) || !slices.Contains(alice, "admin") {
		t.Fatalf("native=%v alice=%v", native, alice)
	}
	var stale int
	if err := db.QueryRow(`SELECT COUNT(*) FROM permissions_roles
        WHERE role_code='legacy:ERP_WEB:STALE'`).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("stale roles=%d err=%v", stale, err)
	}
}

func assertMenuUnchanged(t *testing.T, db *sql.DB) {
	t.Helper()
	const want = `[{"code":"content","required_permission":"content:read"}]`
	var got string
	if err := db.QueryRow(`SELECT menu_json FROM permissions_menus WHERE client_id='sverp-web'`).Scan(&got); err != nil {
		t.Fatalf("query menu: %v", err)
	}
	if got != want {
		t.Fatalf("menu = %q, want %q", got, want)
	}
}

const testTargetSchema = `
CREATE TABLE users(id TEXT PRIMARY KEY,external_id TEXT,provider TEXT,email TEXT,name TEXT,
 attributes TEXT NOT NULL DEFAULT '{}',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE password_credentials(user_id TEXT PRIMARY KEY,hash TEXT NOT NULL,updated_at INTEGER);
CREATE TABLE clients(id TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 1,tenant_id TEXT NOT NULL DEFAULT '');
CREATE TABLE permissions_roles(client_id TEXT NOT NULL,role_code TEXT NOT NULL,name TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '',permissions_json TEXT NOT NULL DEFAULT '[]',PRIMARY KEY(client_id,role_code));
CREATE TABLE permissions_assignments(user_id TEXT NOT NULL,client_id TEXT NOT NULL,roles_json TEXT NOT NULL DEFAULT '[]',
 PRIMARY KEY(user_id,client_id));
CREATE TABLE permissions_menus(client_id TEXT PRIMARY KEY,menu_json TEXT NOT NULL DEFAULT '[]');
`

// testTargetSchemaNullableClients is the parity schema with a nullable
// clients.tenant_id (no NOT NULL) — the only fixture in which SQL NULL
// bindings are insertable. Used only by the NULL-binding unit tests; real
// deployments cannot hold NULL (v1 migration: NOT NULL DEFAULT ”).
const testTargetSchemaNullableClients = `
CREATE TABLE users(id TEXT PRIMARY KEY,external_id TEXT,provider TEXT,email TEXT,name TEXT,
 attributes TEXT NOT NULL DEFAULT '{}',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE password_credentials(user_id TEXT PRIMARY KEY,hash TEXT NOT NULL,updated_at INTEGER);
CREATE TABLE clients(id TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 1,tenant_id TEXT);
CREATE TABLE permissions_roles(client_id TEXT NOT NULL,role_code TEXT NOT NULL,name TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '',permissions_json TEXT NOT NULL DEFAULT '[]',PRIMARY KEY(client_id,role_code));
CREATE TABLE permissions_assignments(user_id TEXT NOT NULL,client_id TEXT NOT NULL,roles_json TEXT NOT NULL DEFAULT '[]',
 PRIMARY KEY(user_id,client_id));
CREATE TABLE permissions_menus(client_id TEXT PRIMARY KEY,menu_json TEXT NOT NULL DEFAULT '[]');
`

// testTargetSchemaNoTenantColumn is the pre-gate fixture shape: a clients
// table without tenant_id. Only the missing-column failure test uses it —
// every server-created target has the column (v1 migration), so a table
// without it must fail loudly, not scan blindly.
const testTargetSchemaNoTenantColumn = `
CREATE TABLE users(id TEXT PRIMARY KEY,external_id TEXT,provider TEXT,email TEXT,name TEXT,
 attributes TEXT NOT NULL DEFAULT '{}',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
CREATE TABLE password_credentials(user_id TEXT PRIMARY KEY,hash TEXT NOT NULL,updated_at INTEGER);
CREATE TABLE clients(id TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE permissions_roles(client_id TEXT NOT NULL,role_code TEXT NOT NULL,name TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL DEFAULT '',permissions_json TEXT NOT NULL DEFAULT '[]',PRIMARY KEY(client_id,role_code));
CREATE TABLE permissions_assignments(user_id TEXT NOT NULL,client_id TEXT NOT NULL,roles_json TEXT NOT NULL DEFAULT '[]',
 PRIMARY KEY(user_id,client_id));
CREATE TABLE permissions_menus(client_id TEXT PRIMARY KEY,menu_json TEXT NOT NULL DEFAULT '[]');
`
