package main

import (
	"reflect"
	"sort"
	"testing"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
)

func TestExampleManifestMatchesRelayContracts(t *testing.T) {
	manifest, err := auditgovernance.LoadDesiredManifest(
		"../../ops/deploy/audit-provisioner/desired-state.example.json",
	)
	if err != nil {
		t.Fatal(err)
	}
	assertExampleSources(t, manifest.Sources)
	assertFixedSchemas(t, manifest.Schemas)
	assertBillingSchemas(t, manifest.Schemas)
}

func assertExampleSources(t *testing.T, sources []auditgovernance.DesiredSource) {
	t.Helper()
	want := map[string]string{
		"aero-id":          "aero-id-audit-relay",
		"aero-im":          "aero-im-audit-relay",
		"aero-vault":       "aero-vault-audit-relay",
		"snaplink-billing": "snaplink-billing-audit-relay",
	}
	if len(sources) != len(want) {
		t.Fatalf("sources = %d, want %d", len(sources), len(want))
	}
	for _, source := range sources {
		if !source.Active || !reflect.DeepEqual(source.AllowedClientIDs, []string{want[source.Prefix]}) {
			t.Fatalf("source %q allow-list = %v", source.Prefix, source.AllowedClientIDs)
		}
		if _, err := source.Record(); err != nil {
			t.Fatalf("source %q is not tenant-derived: %v", source.Prefix, err)
		}
	}
}

func assertFixedSchemas(t *testing.T, schemas []auditgovernance.DesiredSchema) {
	t.Helper()
	want := map[string]string{
		"aero.id.audit-fact":  "personal",
		"aero.im.security":    "confidential",
		"aero.vault.security": "confidential",
	}
	for schemaID, classification := range want {
		schema := findSchema(t, schemas, schemaID)
		if schema.EventType != schemaID || schema.Classification != classification || !schema.Active {
			t.Fatalf("fixed schema %q contract drifted: %+v", schemaID, schema)
		}
	}
	vault := findSchema(t, schemas, "aero.vault.security")
	wantAllowed := []string{"detail_sha256", "fact_kind", "object_size_bytes", "request_id", "storage_backend"}
	if !reflect.DeepEqual(vault.RequiredFields, []string{"fact_kind"}) ||
		!reflect.DeepEqual(vault.AllowedFields, wantAllowed) {
		t.Fatalf("Vault payload contract drifted: required=%v allowed=%v", vault.RequiredFields, vault.AllowedFields)
	}
}

func assertBillingSchemas(t *testing.T, schemas []auditgovernance.DesiredSchema) {
	t.Helper()
	want := []tenantcommerce.EventType{
		tenantcommerce.EventSubscriptionCreated, tenantcommerce.EventSubscriptionPlanChanged,
		tenantcommerce.EventSubscriptionRenewed, tenantcommerce.EventSubscriptionRenewalFailed,
		tenantcommerce.EventSubscriptionStatusChanged, tenantcommerce.EventEntitlementPublished,
		tenantcommerce.EventWalletCreditPosted, tenantcommerce.EventWalletDebitPosted,
		tenantcommerce.EventWalletAdjustmentPosted, tenantcommerce.EventWalletFrozen,
		tenantcommerce.EventTopUpCreated, tenantcommerce.EventTopUpSucceeded,
		tenantcommerce.EventTopUpFailed, tenantcommerce.EventTopUpRefunded,
		tenantcommerce.EventTopUpChargeback, tenantcommerce.EventTopUpChargebackReversed,
		tenantcommerce.EventUsageRollupClosed,
	}
	actual := make([]string, 0, len(want))
	for _, schema := range schemas {
		if len(schema.SchemaID) >= len("snaplink.billing.") &&
			schema.SchemaID[:len("snaplink.billing.")] == "snaplink.billing." {
			if schema.EventType != schema.SchemaID || schema.Classification != "financial" ||
				!reflect.DeepEqual(schema.RequiredFields, []string{"facts", "payload_digest"}) ||
				!reflect.DeepEqual(schema.AllowedFields, []string{"facts", "payload_digest"}) {
				t.Fatalf("Billing schema drifted: %+v", schema)
			}
			actual = append(actual, schema.SchemaID)
		}
	}
	expected := make([]string, 0, len(want))
	for _, eventType := range want {
		expected = append(expected, string(eventType))
	}
	sort.Strings(expected)
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("Billing event schemas = %v, want %v", actual, expected)
	}
}

func findSchema(
	t *testing.T, schemas []auditgovernance.DesiredSchema, schemaID string,
) auditgovernance.DesiredSchema {
	t.Helper()
	for _, schema := range schemas {
		if schema.SchemaID == schemaID {
			return schema
		}
	}
	t.Fatalf("schema %q missing", schemaID)
	return auditgovernance.DesiredSchema{}
}
