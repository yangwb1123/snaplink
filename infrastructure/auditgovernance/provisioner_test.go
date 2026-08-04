package auditgovernance

import (
	"context"
	"errors"
	"testing"
	"time"
)

type memoryControl struct {
	tenants     map[string]TenantRecord
	sources     map[string]map[string]SourceRecord
	schemas     map[string]map[string]SchemaRecord
	tenantRace  bool
	sourceRace  bool
	schemaRace  bool
	createCalls int
}

func newMemoryControl() *memoryControl {
	return &memoryControl{
		tenants: map[string]TenantRecord{}, sources: map[string]map[string]SourceRecord{},
		schemas: map[string]map[string]SchemaRecord{},
	}
}

func (control *memoryControl) ListTenants(context.Context) ([]TenantRecord, error) {
	result := make([]TenantRecord, 0, len(control.tenants))
	for _, tenant := range control.tenants {
		result = append(result, tenant)
	}
	return result, nil
}

func (control *memoryControl) CreateTenant(_ context.Context, tenant TenantRecord) (TenantRecord, error) {
	control.createCalls++
	tenant.CreatedAt = time.Now()
	control.tenants[tenant.ID] = tenant
	if control.tenantRace {
		control.tenantRace = false
		return TenantRecord{}, ErrControlConflict
	}
	return tenant, nil
}

func (control *memoryControl) ListSources(_ context.Context, tenantID string) ([]SourceRecord, error) {
	var result []SourceRecord
	for _, source := range control.sources[tenantID] {
		result = append(result, source)
	}
	return result, nil
}

func (control *memoryControl) CreateSource(_ context.Context, source SourceRecord) (SourceRecord, error) {
	control.createCalls++
	if control.sources[source.TenantID] == nil {
		control.sources[source.TenantID] = map[string]SourceRecord{}
	}
	source.CreatedAt = time.Now()
	control.sources[source.TenantID][source.ID] = source
	if control.sourceRace {
		control.sourceRace = false
		return SourceRecord{}, ErrControlConflict
	}
	return source, nil
}

func (control *memoryControl) ListSchemas(_ context.Context, tenantID string) ([]SchemaRecord, error) {
	var result []SchemaRecord
	for _, schema := range control.schemas[tenantID] {
		result = append(result, schema)
	}
	return result, nil
}

func (control *memoryControl) CreateSchema(_ context.Context, schema SchemaRecord) (SchemaRecord, error) {
	control.createCalls++
	if control.schemas[schema.TenantID] == nil {
		control.schemas[schema.TenantID] = map[string]SchemaRecord{}
	}
	schema.CreatedAt = time.Now()
	control.schemas[schema.TenantID][schemaKey(schema)] = schema
	if control.schemaRace {
		control.schemaRace = false
		return SchemaRecord{}, ErrControlConflict
	}
	return schema, nil
}

func TestProvisionerCreatesOnlyAndReconciles409Races(t *testing.T) {
	control := newMemoryControl()
	control.tenantRace, control.sourceRace, control.schemaRace = true, true, true
	provisioner, _ := NewProvisioner(control)
	manifest := testDesiredManifest(1)
	result, err := provisioner.Apply(t.Context(), manifest)
	if err != nil || result.TenantsCreated != 1 || result.SourcesCreated != 1 || result.SchemasCreated != 1 {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	before := control.createCalls
	result, err = provisioner.Apply(t.Context(), manifest)
	if err != nil || control.createCalls != before || result.TenantsCreated+result.SourcesCreated+result.SchemasCreated != 0 {
		t.Fatalf("idempotent result=%+v calls=%d error=%v", result, control.createCalls, err)
	}
	omitted := testDesiredManifest(2)
	omitted.Sources, omitted.Schemas = nil, nil
	if _, err := provisioner.Apply(t.Context(), omitted); err != nil {
		t.Fatal(err)
	}
	if len(control.sources["tenant-a"]) != 1 || len(control.schemas["tenant-a"]) != 1 {
		t.Fatal("manifest omission deleted remote state")
	}
}

func TestProvisionerRejectsRevisionDriftAndRecoversOriginal(t *testing.T) {
	control := newMemoryControl()
	provisioner, _ := NewProvisioner(control)
	applied := testDesiredManifest(3)
	if _, err := provisioner.Apply(t.Context(), applied); err != nil {
		t.Fatal(err)
	}
	stale := testDesiredManifest(2)
	if _, err := provisioner.Apply(t.Context(), stale); !errors.Is(err, ErrDesiredStale) {
		t.Fatalf("stale error=%v", err)
	}
	conflict := applied
	conflict.Tenants = append([]DesiredTenant(nil), applied.Tenants...)
	conflict.Tenants[0].Name = "Changed"
	if _, err := provisioner.Apply(t.Context(), conflict); !errors.Is(err, ErrDesiredConflict) {
		t.Fatalf("conflict error=%v", err)
	}
	if _, err := provisioner.Apply(t.Context(), applied); err != nil || provisioner.AppliedRevision() != 3 {
		t.Fatalf("original did not recover: revision=%d error=%v", provisioner.AppliedRevision(), err)
	}
	newer := testDesiredManifest(4)
	if _, err := provisioner.Apply(t.Context(), newer); err != nil || provisioner.AppliedRevision() != 4 {
		t.Fatalf("newer revision did not recover: revision=%d error=%v", provisioner.AppliedRevision(), err)
	}
}

func TestProvisionerCopiesAppliedManifestBeforeRevisionComparison(t *testing.T) {
	control := newMemoryControl()
	provisioner, _ := NewProvisioner(control)
	manifest := testDesiredManifest(1)
	if _, err := provisioner.Apply(t.Context(), manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Sources[0].AllowedClientIDs[0] = "mutated"
	manifest.Schemas[0].RequiredFields = append(manifest.Schemas[0].RequiredFields, "mutated")
	if _, err := provisioner.Apply(t.Context(), testDesiredManifest(1)); err != nil {
		t.Fatalf("caller mutation changed applied state: %v", err)
	}
}

func TestProvisionerFailsClosedOnRemoteSecurityDrift(t *testing.T) {
	control := newMemoryControl()
	manifest := testDesiredManifest(1)
	tenant := manifest.Tenants[0].Record()
	control.tenants[tenant.ID] = tenant
	source, _ := manifest.Sources[0].Record()
	source.AllowedClientIDs = append(source.AllowedClientIDs, "unexpected-client")
	control.sources[tenant.ID] = map[string]SourceRecord{source.ID: source}
	provisioner, _ := NewProvisioner(control)
	if _, err := provisioner.Apply(t.Context(), manifest); !errors.Is(err, ErrRemoteDrift) {
		t.Fatalf("drift error=%v", err)
	}
	if provisioner.AppliedRevision() != 0 {
		t.Fatalf("failed manifest became applied: %d", provisioner.AppliedRevision())
	}
}

func TestProvisionerRechecksSameRevisionAndPreservesAppliedState(t *testing.T) {
	control := newMemoryControl()
	provisioner, _ := NewProvisioner(control)
	manifest := testDesiredManifest(7)
	if _, err := provisioner.Apply(t.Context(), manifest); err != nil {
		t.Fatal(err)
	}
	source, _ := manifest.Sources[0].Record()
	control.sources[source.TenantID][source.ID] = SourceRecord{
		ID: source.ID, TenantID: source.TenantID, Name: source.Name,
		AllowedClientIDs: []string{"widened-client"}, Active: true,
	}
	if _, err := provisioner.Apply(t.Context(), manifest); !errors.Is(err, ErrRemoteDrift) {
		t.Fatalf("same-revision drift error=%v", err)
	}
	if provisioner.AppliedRevision() != 7 {
		t.Fatalf("remote drift replaced applied revision: %d", provisioner.AppliedRevision())
	}
	control.sources[source.TenantID][source.ID] = source
	if _, err := provisioner.Apply(t.Context(), manifest); err != nil {
		t.Fatalf("restored remote state did not recover: %v", err)
	}
}

func testDesiredManifest(revision uint64) DesiredManifest {
	return DesiredManifest{
		Revision: revision,
		Tenants:  []DesiredTenant{{ID: "tenant-a", Name: "Tenant A", Active: true, EventsPerSecond: 100, Burst: 20}},
		Sources: []DesiredSource{{
			TenantID: "tenant-a", Prefix: "aero-id", Name: "Aero ID",
			AllowedClientIDs: []string{"aero-id-relay"}, Active: true,
		}},
		Schemas: []DesiredSchema{{
			TenantID: "tenant-a", SchemaID: "aero.id.audit-fact", Version: 1,
			EventType: "aero.id.audit-fact", Classification: "personal", Active: true,
		}},
	}
}

var _ ControlPlane = (*memoryControl)(nil)
