package auditgovernance

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"
)

var (
	ErrDesiredStale    = errors.New("audit governance: desired revision is stale")
	ErrDesiredConflict = errors.New("audit governance: desired revision content conflict")
	ErrRemoteDrift     = errors.New("audit governance: remote desired-state drift")
)

type ReconcileResult struct {
	Revision       uint64
	TenantsCreated int
	SourcesCreated int
	SchemasCreated int
}

type Provisioner struct {
	control ControlPlane
	mu      sync.Mutex
	applied *DesiredManifest
}

func NewProvisioner(control ControlPlane) (*Provisioner, error) {
	if control == nil {
		return nil, ErrInvalidConfig
	}
	return &Provisioner{control: control}, nil
}

func (provisioner *Provisioner) Apply(ctx context.Context, desired DesiredManifest) (ReconcileResult, error) {
	if err := desired.Normalize(); err != nil {
		return ReconcileResult{}, err
	}
	provisioner.mu.Lock()
	defer provisioner.mu.Unlock()
	if err := provisioner.checkRevision(desired); err != nil {
		return ReconcileResult{Revision: desired.Revision}, err
	}
	result := ReconcileResult{Revision: desired.Revision}
	if err := provisioner.reconcileTenants(ctx, desired.Tenants, &result); err != nil {
		return result, err
	}
	if err := provisioner.reconcileSources(ctx, desired.Sources, &result); err != nil {
		return result, err
	}
	if err := provisioner.reconcileSchemas(ctx, desired.Schemas, &result); err != nil {
		return result, err
	}
	copyManifest := cloneDesiredManifest(desired)
	provisioner.applied = &copyManifest
	return result, nil
}

func (provisioner *Provisioner) checkRevision(desired DesiredManifest) error {
	if provisioner.applied == nil {
		return nil
	}
	if desired.Revision < provisioner.applied.Revision {
		return ErrDesiredStale
	}
	if desired.Revision == provisioner.applied.Revision && !DesiredManifestsEqual(desired, *provisioner.applied) {
		return ErrDesiredConflict
	}
	return nil
}

func (provisioner *Provisioner) AppliedRevision() uint64 {
	provisioner.mu.Lock()
	defer provisioner.mu.Unlock()
	if provisioner.applied == nil {
		return 0
	}
	return provisioner.applied.Revision
}

func (provisioner *Provisioner) reconcileTenants(
	ctx context.Context, desired []DesiredTenant, result *ReconcileResult,
) error {
	remote, err := provisioner.control.ListTenants(ctx)
	if err != nil {
		return err
	}
	indexed, err := indexTenants(remote)
	if err != nil {
		return err
	}
	for _, tenant := range desired {
		if current, exists := indexed[tenant.ID]; exists {
			if !tenantRecordEqual(current, tenant.Record()) {
				return fmt.Errorf("%w: tenant mismatch", ErrRemoteDrift)
			}
			continue
		}
		if err := provisioner.createTenant(ctx, tenant.Record()); err != nil {
			return err
		}
		result.TenantsCreated++
	}
	return nil
}

func (provisioner *Provisioner) createTenant(ctx context.Context, desired TenantRecord) error {
	created, err := provisioner.control.CreateTenant(ctx, desired)
	if err == nil {
		return requireTenantMatch(created, desired)
	}
	if !errors.Is(err, ErrControlConflict) {
		return err
	}
	remote, listErr := provisioner.control.ListTenants(ctx)
	if listErr != nil {
		return listErr
	}
	indexed, indexErr := indexTenants(remote)
	if indexErr != nil {
		return indexErr
	}
	return requireTenantMatch(indexed[desired.ID], desired)
}

func requireTenantMatch(actual, desired TenantRecord) error {
	if !tenantRecordEqual(actual, desired) {
		return fmt.Errorf("%w: tenant create race", ErrRemoteDrift)
	}
	return nil
}

func indexTenants(input []TenantRecord) (map[string]TenantRecord, error) {
	result := make(map[string]TenantRecord, len(input))
	for _, tenant := range input {
		if tenant.ID == "" {
			return nil, ErrInvalidReceipt
		}
		if _, duplicate := result[tenant.ID]; duplicate {
			return nil, ErrInvalidReceipt
		}
		result[tenant.ID] = tenant
	}
	return result, nil
}

func tenantRecordEqual(left, right TenantRecord) bool {
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	return reflect.DeepEqual(left, right)
}

func (provisioner *Provisioner) reconcileSources(
	ctx context.Context, desired []DesiredSource, result *ReconcileResult,
) error {
	grouped := groupDesiredSources(desired)
	for _, tenantID := range sortedSourceTenants(grouped) {
		if err := provisioner.reconcileTenantSources(ctx, tenantID, grouped[tenantID], result); err != nil {
			return err
		}
	}
	return nil
}

func (provisioner *Provisioner) reconcileTenantSources(
	ctx context.Context, tenantID string, desired []DesiredSource, result *ReconcileResult,
) error {
	remote, err := provisioner.control.ListSources(ctx, tenantID)
	if err != nil {
		return err
	}
	indexed, err := indexSources(remote)
	if err != nil {
		return err
	}
	for _, source := range desired {
		record, recordErr := source.Record()
		if recordErr != nil {
			return recordErr
		}
		if current, exists := indexed[record.ID]; exists {
			if !sourceRecordEqual(current, record) {
				return fmt.Errorf("%w: source mismatch", ErrRemoteDrift)
			}
			continue
		}
		if err := provisioner.createSource(ctx, record); err != nil {
			return err
		}
		result.SourcesCreated++
	}
	return nil
}

func (provisioner *Provisioner) createSource(ctx context.Context, desired SourceRecord) error {
	created, err := provisioner.control.CreateSource(ctx, desired)
	if err == nil {
		return requireSourceMatch(created, desired)
	}
	if !errors.Is(err, ErrControlConflict) {
		return err
	}
	remote, listErr := provisioner.control.ListSources(ctx, desired.TenantID)
	if listErr != nil {
		return listErr
	}
	indexed, indexErr := indexSources(remote)
	if indexErr != nil {
		return indexErr
	}
	return requireSourceMatch(indexed[desired.ID], desired)
}

func requireSourceMatch(actual, desired SourceRecord) error {
	if !sourceRecordEqual(actual, desired) {
		return fmt.Errorf("%w: source create race", ErrRemoteDrift)
	}
	return nil
}

func indexSources(input []SourceRecord) (map[string]SourceRecord, error) {
	result := make(map[string]SourceRecord, len(input))
	for _, source := range input {
		if source.ID == "" {
			return nil, ErrInvalidReceipt
		}
		if _, duplicate := result[source.ID]; duplicate {
			return nil, ErrInvalidReceipt
		}
		result[source.ID] = source
	}
	return result, nil
}

func sourceRecordEqual(left, right SourceRecord) bool {
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	left.AllowedClientIDs = append([]string(nil), left.AllowedClientIDs...)
	right.AllowedClientIDs = append([]string(nil), right.AllowedClientIDs...)
	sort.Strings(left.AllowedClientIDs)
	sort.Strings(right.AllowedClientIDs)
	return reflect.DeepEqual(left, right)
}

func groupDesiredSources(input []DesiredSource) map[string][]DesiredSource {
	result := make(map[string][]DesiredSource)
	for _, source := range input {
		result[source.TenantID] = append(result[source.TenantID], source)
	}
	return result
}

func sortedSourceTenants(input map[string][]DesiredSource) []string {
	result := make([]string, 0, len(input))
	for tenantID := range input {
		result = append(result, tenantID)
	}
	sort.Strings(result)
	return result
}

func (provisioner *Provisioner) reconcileSchemas(
	ctx context.Context, desired []DesiredSchema, result *ReconcileResult,
) error {
	grouped := groupDesiredSchemas(desired)
	for _, tenantID := range sortedSchemaTenants(grouped) {
		if err := provisioner.reconcileTenantSchemas(ctx, tenantID, grouped[tenantID], result); err != nil {
			return err
		}
	}
	return nil
}

func (provisioner *Provisioner) reconcileTenantSchemas(
	ctx context.Context, tenantID string, desired []DesiredSchema, result *ReconcileResult,
) error {
	remote, err := provisioner.control.ListSchemas(ctx, tenantID)
	if err != nil {
		return err
	}
	indexed, err := indexSchemas(remote)
	if err != nil {
		return err
	}
	for _, schema := range desired {
		record := schema.Record()
		if current, exists := indexed[schemaKey(record)]; exists {
			if !schemaRecordEqual(current, record) {
				return fmt.Errorf("%w: schema mismatch", ErrRemoteDrift)
			}
			continue
		}
		if err := provisioner.createSchema(ctx, record); err != nil {
			return err
		}
		result.SchemasCreated++
	}
	return nil
}

func (provisioner *Provisioner) createSchema(ctx context.Context, desired SchemaRecord) error {
	created, err := provisioner.control.CreateSchema(ctx, desired)
	if err == nil {
		return requireSchemaMatch(created, desired)
	}
	if !errors.Is(err, ErrControlConflict) {
		return err
	}
	remote, listErr := provisioner.control.ListSchemas(ctx, desired.TenantID)
	if listErr != nil {
		return listErr
	}
	indexed, indexErr := indexSchemas(remote)
	if indexErr != nil {
		return indexErr
	}
	return requireSchemaMatch(indexed[schemaKey(desired)], desired)
}

func requireSchemaMatch(actual, desired SchemaRecord) error {
	if !schemaRecordEqual(actual, desired) {
		return fmt.Errorf("%w: schema create race", ErrRemoteDrift)
	}
	return nil
}

func indexSchemas(input []SchemaRecord) (map[string]SchemaRecord, error) {
	result := make(map[string]SchemaRecord, len(input))
	for _, schema := range input {
		if schema.SchemaID == "" || schema.Version <= 0 {
			return nil, ErrInvalidReceipt
		}
		key := schemaKey(schema)
		if _, duplicate := result[key]; duplicate {
			return nil, ErrInvalidReceipt
		}
		result[key] = schema
	}
	return result, nil
}

func schemaRecordEqual(left, right SchemaRecord) bool {
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	canonicalizeSchemaRecord(&left)
	canonicalizeSchemaRecord(&right)
	return reflect.DeepEqual(left, right)
}

func canonicalizeSchemaRecord(schema *SchemaRecord) {
	schema.RequiredFields = canonicalRecordFields(schema.RequiredFields)
	schema.AllowedFields = canonicalRecordFields(schema.AllowedFields)
	schema.EncryptedFields = canonicalRecordFields(schema.EncryptedFields)
	schema.SearchableFields = canonicalRecordFields(schema.SearchableFields)
}

func canonicalRecordFields(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	result := append([]string(nil), input...)
	sort.Strings(result)
	return result
}

func schemaKey(schema SchemaRecord) string {
	return fmt.Sprintf("%s\x00%s\x00%d", schema.TenantID, schema.SchemaID, schema.Version)
}

func groupDesiredSchemas(input []DesiredSchema) map[string][]DesiredSchema {
	result := make(map[string][]DesiredSchema)
	for _, schema := range input {
		result[schema.TenantID] = append(result[schema.TenantID], schema)
	}
	return result
}

func sortedSchemaTenants(input map[string][]DesiredSchema) []string {
	result := make([]string, 0, len(input))
	for tenantID := range input {
		result = append(result, tenantID)
	}
	sort.Strings(result)
	return result
}
