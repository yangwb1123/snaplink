package auditgovernance

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	maxDesiredManifestBytes = 1 << 20
	maxDesiredRecords       = 10_000
	maxTenantIDBytes        = 128
	maxDisplayNameBytes     = 256
	maxRegionBytes          = 128
	maxClientIDBytes        = 256
)

var ErrDesiredManifest = errors.New("audit governance: invalid desired-state manifest")

// DesiredManifest is a strict, create-only tenant and source declaration.
// Source IDs are derived during validation and never accepted from JSON.
type DesiredManifest struct {
	Revision uint64          `json:"revision"`
	Tenants  []DesiredTenant `json:"tenants"`
	Sources  []DesiredSource `json:"sources"`
	Schemas  []DesiredSchema `json:"schemas"`
}

type DesiredTenant struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	HomeRegion      string `json:"home_region"`
	DataRegion      string `json:"data_region"`
	Active          bool   `json:"active"`
	EventsPerSecond int    `json:"events_per_second"`
	Burst           int    `json:"burst"`
}

type DesiredSource struct {
	TenantID         string   `json:"tenant_id"`
	Prefix           string   `json:"prefix"`
	Name             string   `json:"name"`
	AllowedClientIDs []string `json:"allowed_client_ids"`
	Active           bool     `json:"active"`
}

type DesiredSchema struct {
	TenantID         string   `json:"tenant_id"`
	SchemaID         string   `json:"schema_id"`
	Version          int      `json:"version"`
	EventType        string   `json:"event_type"`
	RequiredFields   []string `json:"required_fields"`
	AllowedFields    []string `json:"allowed_fields"`
	EncryptedFields  []string `json:"encrypted_fields"`
	SearchableFields []string `json:"searchable_fields"`
	Classification   string   `json:"classification"`
	Active           bool     `json:"active"`
}

type TenantRecord struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	HomeRegion      string    `json:"home_region"`
	DataRegion      string    `json:"data_region"`
	Active          bool      `json:"active"`
	EventsPerSecond int       `json:"events_per_second"`
	Burst           int       `json:"burst"`
	CreatedAt       time.Time `json:"created_at,omitempty"`
}

type SourceRecord struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	Name             string    `json:"name"`
	AllowedClientIDs []string  `json:"allowed_client_ids"`
	Active           bool      `json:"active"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
}

type SchemaRecord struct {
	TenantID         string    `json:"tenant_id"`
	SchemaID         string    `json:"schema_id"`
	Version          int       `json:"version"`
	EventType        string    `json:"event_type"`
	RequiredFields   []string  `json:"required_fields"`
	AllowedFields    []string  `json:"allowed_fields"`
	EncryptedFields  []string  `json:"encrypted_fields"`
	SearchableFields []string  `json:"searchable_fields"`
	Classification   string    `json:"classification"`
	Active           bool      `json:"active"`
	CreatedAt        time.Time `json:"created_at,omitempty"`
}

func LoadDesiredManifest(path string) (DesiredManifest, error) {
	file, size, err := openDesiredManifest(path)
	if err != nil {
		return DesiredManifest{}, err
	}
	defer file.Close()
	manifest, err := decodeDesiredManifest(io.LimitReader(file, size+1))
	if err != nil {
		return DesiredManifest{}, err
	}
	if err := verifyDesiredManifest(path, file, size); err != nil {
		return DesiredManifest{}, err
	}
	if err := manifest.Normalize(); err != nil {
		return DesiredManifest{}, err
	}
	return manifest, nil
}

func verifyDesiredManifest(path string, file *os.File, expectedSize int64) error {
	opened, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !safeManifestInfo(opened) || !safeManifestInfo(current) ||
		opened.Size() != expectedSize || !os.SameFile(opened, current) {
		return fmt.Errorf("%w: file changed", ErrDesiredManifest)
	}
	return nil
}

func openDesiredManifest(path string) (*os.File, int64, error) {
	before, err := os.Lstat(path)
	if err != nil || !safeManifestInfo(before) {
		return nil, 0, fmt.Errorf("%w: unsafe file", ErrDesiredManifest)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: open", ErrDesiredManifest)
	}
	after, err := file.Stat()
	if err != nil || !safeManifestInfo(after) || !os.SameFile(before, after) {
		file.Close()
		return nil, 0, fmt.Errorf("%w: file changed", ErrDesiredManifest)
	}
	return file, after.Size(), nil
}

func safeManifestInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Size() <= maxDesiredManifestBytes &&
		info.Mode().Perm()&0o022 == 0
}

func decodeDesiredManifest(reader io.Reader) (DesiredManifest, error) {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var manifest DesiredManifest
	if err := decoder.Decode(&manifest); err != nil {
		return DesiredManifest{}, fmt.Errorf("%w: decode", ErrDesiredManifest)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return DesiredManifest{}, fmt.Errorf("%w: trailing data", ErrDesiredManifest)
	}
	return manifest, nil
}

func (manifest *DesiredManifest) Normalize() error {
	if manifest == nil || manifest.Revision == 0 || len(manifest.Tenants) > maxDesiredRecords ||
		len(manifest.Sources) > maxDesiredRecords || len(manifest.Schemas) > maxDesiredRecords {
		return ErrDesiredManifest
	}
	tenants, err := normalizeDesiredTenants(manifest.Tenants)
	if err != nil {
		return err
	}
	sources, err := normalizeDesiredSources(manifest.Sources, tenants)
	if err != nil {
		return err
	}
	schemas, err := normalizeDesiredSchemas(manifest.Schemas, tenants)
	if err != nil {
		return err
	}
	if !sourcesHaveSchemas(sources, schemas) {
		return ErrDesiredManifest
	}
	manifest.Tenants, manifest.Sources, manifest.Schemas = tenants, sources, schemas
	return nil
}

func sourcesHaveSchemas(sources []DesiredSource, schemas []DesiredSchema) bool {
	covered := make(map[string]struct{}, len(schemas))
	for _, schema := range schemas {
		covered[schema.TenantID] = struct{}{}
	}
	for _, source := range sources {
		if _, ok := covered[source.TenantID]; !ok {
			return false
		}
	}
	return true
}

func normalizeDesiredSchemas(input []DesiredSchema, tenants []DesiredTenant) ([]DesiredSchema, error) {
	result := append([]DesiredSchema(nil), input...)
	tenantIDs := make(map[string]struct{}, len(tenants))
	for _, tenant := range tenants {
		tenantIDs[tenant.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(result))
	for index := range result {
		if _, ok := tenantIDs[result[index].TenantID]; !ok {
			return nil, ErrDesiredManifest
		}
		if err := normalizeDesiredSchema(&result[index], seen); err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TenantID != result[j].TenantID {
			return result[i].TenantID < result[j].TenantID
		}
		if result[i].SchemaID != result[j].SchemaID {
			return result[i].SchemaID < result[j].SchemaID
		}
		return result[i].Version < result[j].Version
	})
	return result, nil
}

func normalizeDesiredSchema(schema *DesiredSchema, seen map[string]struct{}) error {
	if schema == nil || !canonicalText(schema.TenantID, maxTenantIDBytes, false) ||
		!canonicalText(schema.SchemaID, maxDisplayNameBytes, false) || schema.Version <= 0 ||
		!canonicalText(schema.EventType, maxDisplayNameBytes, false) ||
		!canonicalText(schema.Classification, maxDisplayNameBytes, false) || !schema.Active {
		return ErrDesiredManifest
	}
	fields := []*[]string{
		&schema.RequiredFields, &schema.AllowedFields, &schema.EncryptedFields, &schema.SearchableFields,
	}
	for _, fieldSet := range fields {
		normalized, err := normalizeSchemaFields(*fieldSet)
		if err != nil {
			return err
		}
		*fieldSet = normalized
	}
	if !schemaFieldSetsValid(*schema) {
		return ErrDesiredManifest
	}
	key := fmt.Sprintf("%s\x00%s\x00%d", schema.TenantID, schema.SchemaID, schema.Version)
	if _, duplicate := seen[key]; duplicate {
		return ErrDesiredManifest
	}
	seen[key] = struct{}{}
	return nil
}

func normalizeSchemaFields(input []string) ([]string, error) {
	if len(input) > maxDesiredRecords {
		return nil, ErrDesiredManifest
	}
	result := append([]string(nil), input...)
	sort.Strings(result)
	for index, field := range result {
		if !canonicalText(field, maxDisplayNameBytes, false) || index > 0 && result[index-1] == field {
			return nil, ErrDesiredManifest
		}
	}
	return result, nil
}

func schemaFieldSetsValid(schema DesiredSchema) bool {
	if len(schema.AllowedFields) == 0 {
		return true
	}
	allowed := make(map[string]struct{}, len(schema.AllowedFields))
	for _, field := range schema.AllowedFields {
		allowed[field] = struct{}{}
	}
	for _, fields := range [][]string{schema.RequiredFields, schema.EncryptedFields, schema.SearchableFields} {
		for _, field := range fields {
			if _, ok := allowed[field]; !ok {
				return false
			}
		}
	}
	return true
}

func normalizeDesiredTenants(input []DesiredTenant) ([]DesiredTenant, error) {
	result := append([]DesiredTenant(nil), input...)
	seen := make(map[string]struct{}, len(result))
	for _, tenant := range result {
		if !validDesiredTenant(tenant) {
			return nil, ErrDesiredManifest
		}
		if _, duplicate := seen[tenant.ID]; duplicate {
			return nil, ErrDesiredManifest
		}
		seen[tenant.ID] = struct{}{}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func validDesiredTenant(tenant DesiredTenant) bool {
	return canonicalText(tenant.ID, maxTenantIDBytes, false) &&
		canonicalText(tenant.Name, maxDisplayNameBytes, false) &&
		canonicalText(tenant.HomeRegion, maxRegionBytes, true) &&
		canonicalText(tenant.DataRegion, maxRegionBytes, true) && tenant.Active &&
		tenant.EventsPerSecond >= 0 && tenant.Burst >= 0
}

func normalizeDesiredSources(input []DesiredSource, tenants []DesiredTenant) ([]DesiredSource, error) {
	result := append([]DesiredSource(nil), input...)
	tenantIDs := make(map[string]struct{}, len(tenants))
	for _, tenant := range tenants {
		tenantIDs[tenant.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(result))
	for index := range result {
		if _, ok := tenantIDs[result[index].TenantID]; !ok {
			return nil, ErrDesiredManifest
		}
		if err := normalizeDesiredSource(&result[index], seen); err != nil {
			return nil, err
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].TenantID == result[j].TenantID {
			return result[i].Prefix < result[j].Prefix
		}
		return result[i].TenantID < result[j].TenantID
	})
	return result, nil
}

func normalizeDesiredSource(source *DesiredSource, seen map[string]struct{}) error {
	if source == nil || !canonicalText(source.TenantID, maxTenantIDBytes, false) ||
		!canonicalText(source.Name, maxDisplayNameBytes, false) || !source.Active {
		return ErrDesiredManifest
	}
	sourceID, err := TenantSourceID(source.Prefix, source.TenantID)
	if err != nil {
		return ErrDesiredManifest
	}
	clients, err := normalizeClientIDs(source.AllowedClientIDs)
	if err != nil {
		return err
	}
	key := source.TenantID + "\x00" + sourceID
	if _, duplicate := seen[key]; duplicate {
		return ErrDesiredManifest
	}
	seen[key] = struct{}{}
	source.AllowedClientIDs = clients
	return nil
}

func normalizeClientIDs(input []string) ([]string, error) {
	if len(input) == 0 || len(input) > maxDesiredRecords {
		return nil, ErrDesiredManifest
	}
	result := append([]string(nil), input...)
	sort.Strings(result)
	for index, clientID := range result {
		if !canonicalText(clientID, maxClientIDBytes, false) || index > 0 && result[index-1] == clientID {
			return nil, ErrDesiredManifest
		}
	}
	return result, nil
}

func canonicalText(value string, limit int, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	return len(value) <= limit && value == strings.TrimSpace(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func (tenant DesiredTenant) Record() TenantRecord {
	return TenantRecord{
		ID: tenant.ID, Name: tenant.Name, HomeRegion: tenant.HomeRegion, DataRegion: tenant.DataRegion,
		Active: tenant.Active, EventsPerSecond: tenant.EventsPerSecond, Burst: tenant.Burst,
	}
}

func (source DesiredSource) Record() (SourceRecord, error) {
	id, err := TenantSourceID(source.Prefix, source.TenantID)
	if err != nil {
		return SourceRecord{}, ErrDesiredManifest
	}
	return SourceRecord{
		ID: id, TenantID: source.TenantID, Name: source.Name,
		AllowedClientIDs: append([]string(nil), source.AllowedClientIDs...), Active: source.Active,
	}, nil
}

func (schema DesiredSchema) Record() SchemaRecord {
	return SchemaRecord{
		TenantID: schema.TenantID, SchemaID: schema.SchemaID, Version: schema.Version,
		EventType: schema.EventType, RequiredFields: append([]string(nil), schema.RequiredFields...),
		AllowedFields:    append([]string(nil), schema.AllowedFields...),
		EncryptedFields:  append([]string(nil), schema.EncryptedFields...),
		SearchableFields: append([]string(nil), schema.SearchableFields...),
		Classification:   schema.Classification, Active: schema.Active,
	}
}

func DesiredManifestsEqual(left, right DesiredManifest) bool {
	return reflect.DeepEqual(left, right)
}

func cloneDesiredManifest(manifest DesiredManifest) DesiredManifest {
	result := manifest
	result.Tenants = append([]DesiredTenant(nil), manifest.Tenants...)
	result.Sources = append([]DesiredSource(nil), manifest.Sources...)
	for index := range result.Sources {
		result.Sources[index].AllowedClientIDs = append([]string(nil), result.Sources[index].AllowedClientIDs...)
	}
	result.Schemas = append([]DesiredSchema(nil), manifest.Schemas...)
	for index := range result.Schemas {
		cloneDesiredSchemaFields(&result.Schemas[index])
	}
	return result
}

func cloneDesiredSchemaFields(schema *DesiredSchema) {
	schema.RequiredFields = append([]string(nil), schema.RequiredFields...)
	schema.AllowedFields = append([]string(nil), schema.AllowedFields...)
	schema.EncryptedFields = append([]string(nil), schema.EncryptedFields...)
	schema.SearchableFields = append([]string(nil), schema.SearchableFields...)
}
