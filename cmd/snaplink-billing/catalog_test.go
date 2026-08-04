package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var shippedCatalogControlledLimits = map[tenantcommerce.LimitKey]struct{}{
	tenantcommerce.LimitUsers: {}, tenantcommerce.LimitClients: {},
	tenantcommerce.LimitSessions: {}, tenantcommerce.LimitTokenRate: {},
	tenantcommerce.LimitStorageBytes: {}, tenantcommerce.LimitStorageObjects: {},
	tenantcommerce.LimitStorageAllocated: {}, tenantcommerce.LimitStorageReclaimed: {},
	tenantcommerce.LimitObjectsCreated: {}, tenantcommerce.LimitObjectsDeleted: {},
	tenantcommerce.LimitMessagesPerMonth: {}, tenantcommerce.LimitNotificationsMonth: {},
	tenantcommerce.LimitAuditRetentionDays: {},
}

func TestPublishCatalogIsStrictAndRestartIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	content := `[{
  "id":"minimal","version":1,"name":"Minimal","status":"active",
  "billing_interval":"month","price":{"currency":"USD","minor_units":1000},
  "features":{"core_sso":true},"limits":{"users":{"soft":8,"hard":10}},
  "created_at":"2026-08-04T00:00:00Z"
}]`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	store := tenantcommerce.NewMemoryStore()
	service, err := tenantcommerce.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := publishCatalog(t.Context(), path, service); err != nil {
			t.Fatal(err)
		}
	}
	plans, err := store.ListPlans(context.Background())
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%v err=%v", plans, err)
	}
}

func TestLoadCatalogRejectsUnknownFieldsAndUnstableTime(t *testing.T) {
	tests := []string{
		`[{"id":"p","unknown":true}]`,
		`[{"id":"p","version":1,"name":"P","status":"active","billing_interval":"none","price":{"currency":"USD","minor_units":0},"features":{},"limits":{}}]`,
		`null`,
	}
	for index, content := range tests {
		path := filepath.Join(t.TempDir(), "catalog.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadCatalog(path); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestShippedProductCatalogPublishesMonthlyAndAnnualPlans(t *testing.T) {
	store := tenantcommerce.NewMemoryStore()
	service, err := tenantcommerce.NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "ops", "product", "catalog.v1.json")
	if err := publishCatalog(t.Context(), path, service); err != nil {
		t.Fatal(err)
	}
	plans, err := store.ListPlans(t.Context())
	if err != nil || len(plans) != 5 {
		t.Fatalf("shipped plans=%d err=%v", len(plans), err)
	}
	wantAnnual := map[string]int64{"team-annual": 49000, "business-annual": 299000}
	for _, plan := range plans {
		price, annual := wantAnnual[plan.ID]
		if !annual {
			continue
		}
		if plan.Interval != tenantcommerce.IntervalYear || plan.Price.MinorUnits != price {
			t.Fatalf("annual plan %q = interval %q price %d", plan.ID, plan.Interval, plan.Price.MinorUnits)
		}
		delete(wantAnnual, plan.ID)
	}
	if len(wantAnnual) != 0 {
		t.Fatalf("missing annual plans: %v", wantAnnual)
	}
}

func TestShippedProductCatalogOnlyPromisesControlledLimits(t *testing.T) {
	path := filepath.Join("..", "..", "ops", "product", "catalog.v1.json")
	plans, err := loadCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range plans {
		for key := range plan.Limits {
			if _, controlled := shippedCatalogControlledLimits[key]; !controlled {
				t.Errorf("plan %q publishes uncontrolled limit %q", plan.ID, key)
			}
		}
	}
}
