package commercehttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func TestPlanCatalogAndSubscriptionCreation(t *testing.T) {
	environment := newTestEnvironment(t)
	plan := commerceTestPlan("minimal", 1)
	response := serveJSON(t, environment.router, http.MethodPost, PathPlans, plan)
	if response.Code != http.StatusCreated {
		t.Fatalf("publish status = %d, body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get(headerCacheControl) != cacheControlNoStore {
		t.Fatalf("cache control = %q", response.Header().Get(headerCacheControl))
	}

	response = serveJSON(t, environment.router, http.MethodGet, PathPlans, nil)
	var catalog struct {
		Plans []*tenantcommerce.Plan `json:"plans"`
		Total int                    `json:"total"`
	}
	decodeResponse(t, response, &catalog)
	if response.Code != http.StatusOK || catalog.Total != 1 || catalog.Plans[0].ID != "minimal" {
		t.Fatalf("catalog = %+v, status=%d", catalog, response.Code)
	}

	body := map[string]any{
		"id": "sub-1", "tenant_id": "tenant-1", "plan_id": "minimal", "plan_version": 1,
	}
	path := "/api/v1/admin/commerce/tenants/tenant-1/subscriptions"
	response = serveJSON(t, environment.router, http.MethodPost, path, body)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", response.Code, response.Body.String())
	}
	if record := environment.observer.latest(); record.Outcome != MutationSucceeded || record.TenantID != "tenant-1" {
		t.Fatalf("observer record = %+v", record)
	}
	response = serveJSON(t, environment.router, http.MethodGet, path, nil)
	var subscriptions struct {
		Items []*tenantcommerce.Subscription `json:"subscriptions"`
		Total int                            `json:"total"`
	}
	decodeResponse(t, response, &subscriptions)
	if response.Code != http.StatusOK || subscriptions.Total != 1 || subscriptions.Items[0].ID != "sub-1" {
		t.Fatalf("subscriptions = %+v, status=%d", subscriptions, response.Code)
	}
}

func TestSubscriptionRejectsPathBodyTenantMismatch(t *testing.T) {
	environment := newTestEnvironment(t)
	if err := environment.service.PublishPlan(t.Context(), commerceTestPlan("minimal", 1)); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"id": "sub-1", "tenant_id": "tenant-2", "plan_id": "minimal", "plan_version": 1,
	}
	path := "/api/v1/admin/commerce/tenants/tenant-1/subscriptions"
	response := serveJSON(t, environment.router, http.MethodPost, path, body)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("mismatch status = %d, body=%s", response.Code, response.Body.String())
	}
	if record := environment.observer.latest(); record.ErrorCode != "invalid_request" {
		t.Fatalf("observer record = %+v", record)
	}
}

func TestSubscriptionLifecycleAndEntitlement(t *testing.T) {
	environment := newTestEnvironment(t)
	subscription := seedSubscription(t, environment)
	publishPlan(t, environment, commerceTestPlan("full", 1))

	path := "/api/v1/admin/commerce/subscriptions/" + subscription.ID + "/plan"
	response := serveJSON(t, environment.router, http.MethodPatch, path, map[string]any{
		"plan_id": "full", "plan_version": 1, "expected_revision": 1,
	})
	assertSubscriptionRevision(t, response, 2, "full")

	path = "/api/v1/admin/commerce/subscriptions/" + subscription.ID + "/status"
	response = serveJSON(t, environment.router, http.MethodPatch, path, map[string]any{
		"status": "paused", "expected_revision": 2,
	})
	assertSubscriptionStatus(t, response, 3, tenantcommerce.SubscriptionPaused)
	response = serveJSON(t, environment.router, http.MethodPatch, path, map[string]any{
		"status": "active", "expected_revision": 3,
	})
	assertSubscriptionStatus(t, response, 4, tenantcommerce.SubscriptionActive)

	path = "/api/v1/admin/commerce/subscriptions/" + subscription.ID + "/renew"
	response = serveJSON(t, environment.router, http.MethodPost, path, map[string]any{"expected_revision": 4})
	assertSubscriptionRevision(t, response, 5, "full")

	path = "/api/v1/admin/commerce/tenants/tenant-1/entitlement"
	response = serveJSON(t, environment.router, http.MethodGet, path, nil)
	var body struct {
		Entitlement *tenantcommerce.EntitlementSnapshot `json:"entitlement"`
	}
	decodeResponse(t, response, &body)
	if response.Code != http.StatusOK || body.Entitlement.Plan.ID != "full" || body.Entitlement.Revision != 5 {
		t.Fatalf("entitlement = %+v, status=%d", body.Entitlement, response.Code)
	}
}

func seedSubscription(t *testing.T, environment *testEnvironment) *tenantcommerce.Subscription {
	t.Helper()
	publishPlan(t, environment, commerceTestPlan("minimal", 1))
	subscription, _, err := environment.service.CreateSubscription(t.Context(), tenantcommerce.CreateSubscriptionCommand{
		ID: "sub-1", TenantID: "tenant-1", Plan: tenantcommerce.PlanRef{ID: "minimal", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	return subscription
}

func publishPlan(t *testing.T, environment *testEnvironment, plan *tenantcommerce.Plan) {
	t.Helper()
	if err := environment.service.PublishPlan(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
}

func assertSubscriptionRevision(
	t *testing.T, response *httptest.ResponseRecorder, revision uint64, planID string,
) {
	t.Helper()
	result := response.Result()
	defer result.Body.Close()
	var body struct {
		Subscription *tenantcommerce.Subscription `json:"subscription"`
	}
	if err := json.NewDecoder(result.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || body.Subscription.Revision != revision || body.Subscription.Plan.ID != planID {
		t.Fatalf("subscription = %+v, status=%d", body.Subscription, result.StatusCode)
	}
}

func assertSubscriptionStatus(
	t *testing.T, response *httptest.ResponseRecorder, revision uint64, status tenantcommerce.SubscriptionStatus,
) {
	t.Helper()
	result := response.Result()
	defer result.Body.Close()
	var body struct {
		Subscription *tenantcommerce.Subscription `json:"subscription"`
	}
	if err := json.NewDecoder(result.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if result.StatusCode != http.StatusOK || body.Subscription.Revision != revision || body.Subscription.Status != status {
		t.Fatalf("subscription = %+v, status=%d", body.Subscription, result.StatusCode)
	}
}
