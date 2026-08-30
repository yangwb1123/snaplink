package meteringhttp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
)

func TestReservationLifecyclePassesBoundIdentity(t *testing.T) {
	deps, usage, _ := defaultDeps()
	router := testRouter(t, deps)
	reserveBody := `{"id":"reservation-1","dimension":"messages_per_month",` +
		`"quantity":2,"ttl_seconds":60}`
	response := serveRequest(router, defaultClaims(ScopeMeteringWrite),
		http.MethodPost, PathReservations, reserveBody, jsonHeaders("reserve-message"))
	if response.Code != http.StatusCreated || usage.reserveEvidence != defaultBinding().Evidence() ||
		usage.reserveCommand.TTL != time.Minute {
		t.Fatalf("reserve response/evidence/command = %d %+v %+v",
			response.Code, usage.reserveEvidence, usage.reserveCommand)
	}
	commitPath := "/api/v1/metering/reservations/reservation-1/commit"
	commitBody := `{"fact_id":"usage-1","metadata":{"resource_type":"message"}}`
	response = serveRequest(router, defaultClaims(ScopeMeteringWrite),
		http.MethodPost, commitPath, commitBody, jsonHeaders("commit-message"))
	if response.Code != http.StatusOK || usage.commitEvidence != defaultBinding().Evidence() ||
		usage.commitID != "reservation-1" || usage.commitCommand.ID != "usage-1" {
		t.Fatalf("commit response/evidence/command = %d %+v %+v",
			response.Code, usage.commitEvidence, usage.commitCommand)
	}
	releasePath := "/api/v1/metering/reservations/reservation-1"
	response = serveRequest(router, defaultClaims(ScopeMeteringWrite),
		http.MethodDelete, releasePath, "", jsonHeaders("release-message"))
	if response.Code != http.StatusOK || usage.releaseEvidence != usage.commitEvidence ||
		usage.releaseID != usage.commitID || usage.releaseKey != "release-message" {
		t.Fatalf("release response/evidence = %d %+v", response.Code, usage.releaseEvidence)
	}
}

func TestReleaseRequiresKeyAndTerminalReleaseState(t *testing.T) {
	deps, usage, _ := defaultDeps()
	router := testRouter(t, deps)
	path := "/api/v1/metering/reservations/reservation-1"
	for _, key := range []string{"", " ", strings.Repeat("x", maxIdempotencyBytes+1)} {
		response := serveRequest(router, defaultClaims(ScopeMeteringWrite), http.MethodDelete,
			path, "", map[string]string{headerIdempotency: key})
		if response.Code != http.StatusBadRequest {
			t.Fatalf("key %q response = %d %s", key, response.Code, response.Body.String())
		}
	}
	if usage.releaseID != "" {
		t.Fatal("invalid release request reached usage service")
	}
	usage.releaseStatus = usageledger.ReservationCommitted
	response := serveRequest(router, defaultClaims(ScopeMeteringWrite), http.MethodDelete,
		path, "", jsonHeaders("release-committed"))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), ErrorReservationConflict) {
		t.Fatalf("committed release response = %d %s", response.Code, response.Body.String())
	}
}

func TestReservationRequestsRejectAuthorityAndUnsafeTTL(t *testing.T) {
	deps, _, _ := defaultDeps()
	router := testRouter(t, deps)
	tests := []struct {
		path string
		body string
	}{
		{PathReservations, `{"tenant_id":"tenant-other","dimension":"messages_per_month",` +
			`"quantity":1,"ttl_seconds":60}`},
		{PathReservations, `{"dimension":"messages_per_month","quantity":1,` +
			`"ttl_seconds":9223372036854775807}`},
		{"/api/v1/metering/reservations/reservation-1/commit",
			`{"source_system":"evil","fact_id":"usage-1"}`},
		{PathReservations, `{"dimension":"messages_per_month","quantity":1,` +
			`"period":` + periodJSON() + `,"ttl_seconds":60}`},
	}
	for _, test := range tests {
		response := serveRequest(router, defaultClaims(ScopeMeteringWrite),
			http.MethodPost, test.path, test.body, jsonHeaders("invalid-reservation"))
		if response.Code != http.StatusBadRequest {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
	}
	response := serveRequest(router, defaultClaims(ScopeMeteringWrite), http.MethodDelete,
		"/api/v1/metering/reservations/reservation-1", `{}`, jsonHeaders("release-invalid"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("release body response = %d %s", response.Code, response.Body.String())
	}
	response = serveRequest(router, defaultClaims(ScopeMeteringWrite), http.MethodDelete,
		"/api/v1/metering/reservations/reservation-1", "", nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("release missing key response = %d %s", response.Code, response.Body.String())
	}
}

func TestEntitlementReadIsNarrowAndBoundToResolvedTenant(t *testing.T) {
	deps, _, entitlements := defaultDeps()
	router := testRouter(t, deps)
	response := serveRequest(router, defaultClaims(ScopeEntitlementRead),
		http.MethodGet, PathEntitlement, "", nil)
	if response.Code != http.StatusOK || entitlements.tenantID != "tenant-1" ||
		!strings.Contains(response.Body.String(), `"tenant_id":"tenant-1"`) {
		t.Fatalf("entitlement response/tenant = %d %q %s",
			response.Code, entitlements.tenantID, response.Body.String())
	}
	response = serveRequest(router, defaultClaims(ScopeEntitlementRead),
		http.MethodGet, PathEntitlement+"?tenant_id=tenant-other", "", nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("query authority response = %d %s", response.Code, response.Body.String())
	}
	entitlements.snapshot.TenantID = "tenant-other"
	response = serveRequest(router, defaultClaims(ScopeEntitlementRead),
		http.MethodGet, PathEntitlement, "", nil)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), ErrorUnavailable) {
		t.Fatalf("mismatched projection response = %d %s", response.Code, response.Body.String())
	}
}

func TestEntitlementRecheckBlocksReboundSourceProjection(t *testing.T) {
	deps, _, _ := defaultDeps()
	original := defaultBinding()
	rebound := defaultBinding()
	rebound.ID, rebound.TenantID, rebound.Revision = "source-2", "tenant-other", 1
	calls := 0
	deps.Sources = sourceResolverStub{resolve: func(
		context.Context, string,
	) (*usageledger.SourceBinding, error) {
		calls++
		if calls == 1 {
			return original, nil
		}
		return rebound, nil
	}}
	response := serveRequest(testRouter(t, deps), defaultClaims(ScopeEntitlementRead),
		http.MethodGet, PathEntitlement, "", nil)
	if response.Code != http.StatusForbidden ||
		!strings.Contains(response.Body.String(), ErrorSourceUnauthorized) ||
		strings.Contains(response.Body.String(), responseEntitlement) {
		t.Fatalf("rebound response = %d %s", response.Code, response.Body.String())
	}
}

func TestConcurrentMachineAppendsRemainBound(t *testing.T) {
	deps, usage, _ := defaultDeps()
	router := testRouter(t, deps)
	errors := make(chan string, 32)
	for index := range 32 {
		go func() {
			body := `{"dimension":"messages_per_month","quantity":1}`
			response := serveRequest(router, defaultClaims(ScopeMeteringWrite),
				http.MethodPost, PathUsageAppend, body, jsonHeaders("message-"+string(rune('a'+index))))
			if response.Code != http.StatusCreated {
				errors <- response.Body.String()
				return
			}
			errors <- ""
		}()
	}
	for range 32 {
		if failure := <-errors; failure != "" {
			t.Fatalf("concurrent append failed: %s", failure)
		}
	}
	usage.mu.Lock()
	defer usage.mu.Unlock()
	if usage.appendCalls != 32 || usage.appendEvidence != defaultBinding().Evidence() {
		t.Fatalf("concurrent calls/evidence = %d %+v", usage.appendCalls, usage.appendEvidence)
	}
}
