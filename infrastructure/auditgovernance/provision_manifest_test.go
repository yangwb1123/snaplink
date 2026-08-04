package auditgovernance

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDesiredManifestIsStrictSafeAndCanonical(t *testing.T) {
	path := writeDesiredManifest(t, `{
  "revision": 7,
  "tenants": [{"id":"tenant-a","name":"Tenant A","home_region":"us-east-1","data_region":"us-east-1","active":true,"events_per_second":100,"burst":20}],
  "sources": [{"tenant_id":"tenant-a","prefix":"aero-id","name":"Aero ID","allowed_client_ids":["relay-z","relay-a"],"active":true}],
  "schemas": [{"tenant_id":"tenant-a","schema_id":"aero.id.audit-fact","version":1,"event_type":"aero.id.audit-fact","required_fields":[],"allowed_fields":[],"encrypted_fields":[],"searchable_fields":[],"classification":"personal","active":true}]
}`)
	manifest, err := LoadDesiredManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Revision != 7 || manifest.Sources[0].AllowedClientIDs[0] != "relay-a" {
		t.Fatalf("manifest was not canonicalized: %+v", manifest)
	}
	record, err := manifest.Sources[0].Record()
	if err != nil {
		t.Fatal(err)
	}
	want, _ := TenantSourceID("aero-id", "tenant-a")
	if record.ID != want {
		t.Fatalf("source ID=%q want=%q", record.ID, want)
	}
}

func TestLoadDesiredManifestRejectsUnknownUnsafeAndIncompleteInput(t *testing.T) {
	unknown := writeDesiredManifest(t, `{"revision":1,"tenants":[],"sources":[],"schemas":[],"extra":true}`)
	if _, err := LoadDesiredManifest(unknown); !errors.Is(err, ErrDesiredManifest) {
		t.Fatalf("unknown field error=%v", err)
	}
	unsafe := writeDesiredManifest(t, `{"revision":1,"tenants":[],"sources":[],"schemas":[]}`)
	if err := os.Chmod(unsafe, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDesiredManifest(unsafe); !errors.Is(err, ErrDesiredManifest) {
		t.Fatalf("unsafe mode error=%v", err)
	}
	target := writeDesiredManifest(t, `{"revision":1,"tenants":[],"sources":[],"schemas":[]}`)
	symlink := filepath.Join(t.TempDir(), "desired-link.json")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDesiredManifest(symlink); !errors.Is(err, ErrDesiredManifest) {
		t.Fatalf("symlink error=%v", err)
	}
	missingSchema := writeDesiredManifest(t, `{
  "revision":1,
  "tenants":[{"id":"tenant-a","name":"Tenant A","home_region":"","data_region":"","active":true,"events_per_second":0,"burst":0}],
  "sources":[{"tenant_id":"tenant-a","prefix":"aero-id","name":"Aero ID","allowed_client_ids":["relay"],"active":true}],
  "schemas":[]
}`)
	if _, err := LoadDesiredManifest(missingSchema); !errors.Is(err, ErrDesiredManifest) {
		t.Fatalf("missing schema error=%v", err)
	}
}

func TestLoadDesiredManifestAcceptsKubernetesProjectedGenerationPath(t *testing.T) {
	mount := t.TempDir()
	generation := filepath.Join(mount, "..2026_08_04")
	if err := os.Mkdir(generation, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(generation, "desired-state.json")
	if err := os.WriteFile(path, []byte(`{"revision":1,"tenants":[],"sources":[],"schemas":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(generation), filepath.Join(mount, "..data")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDesiredManifest(filepath.Join(mount, "..data", "desired-state.json")); err != nil {
		t.Fatalf("projected generation path rejected: %v", err)
	}
}

func TestDesiredManifestRejectsDuplicateOrNonCanonicalSecurityFields(t *testing.T) {
	tests := []DesiredManifest{
		{Revision: 1, Tenants: []DesiredTenant{{ID: " tenant", Name: "Tenant", Active: true}}},
		{Revision: 1, Tenants: []DesiredTenant{{ID: "tenant", Name: "Tenant", Active: true}}, Sources: []DesiredSource{
			{TenantID: "tenant", Prefix: "aero-id", Name: "A", AllowedClientIDs: []string{"relay", "relay"}, Active: true},
		}},
		{Revision: 1, Tenants: []DesiredTenant{{ID: "tenant", Name: "Tenant", Active: true}}, Schemas: []DesiredSchema{
			{TenantID: "tenant", SchemaID: "schema", Version: 1, EventType: "event", AllowedFields: []string{"safe"}, RequiredFields: []string{"missing"}, Active: true},
		}},
		{Revision: 1, Tenants: []DesiredTenant{{ID: "tenant", Name: "Tenant", Active: true}}, Schemas: []DesiredSchema{
			{TenantID: "tenant", SchemaID: "schema", Version: 1, EventType: "event", Active: true},
		}},
	}
	for index := range tests {
		if err := tests[index].Normalize(); !errors.Is(err, ErrDesiredManifest) {
			t.Fatalf("case %d error=%v", index, err)
		}
	}
}

func writeDesiredManifest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "desired.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
