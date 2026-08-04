package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditgovernance"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestQuotaRelayWiringUsesExactMachineContract(t *testing.T) {
	store := newQuotaRelayTestStore()
	sourceID, err := auditgovernance.TenantSourceID(defaultQuotaSourcePrefix, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	var projectionSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case core.PathToken:
			assertQuotaTokenRequest(t, request)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"access_token":"quota-token","token_type":"Bearer","expires_in":300}`)
		case core.PathTenantQuotaProjection:
			projectionSeen = assertQuotaProjectionRequest(t, request, sourceID)
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"tenant_id":"tenant-a","revision":2,"applied":true}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	runner, err := buildQuotaRelay(quotaRelayTestConfig(server.URL), store, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.relay.RunOnce(t.Context())
	if err != nil || result.Delivered != 1 || store.completedRevision != 2 || !projectionSeen {
		t.Fatalf("RunOnce() = %+v, %v; revision=%d seen=%v", result, err, store.completedRevision, projectionSeen)
	}
}

func TestQuotaRelayProjectsCommercialRetentionWithDedicatedPlatformCredential(t *testing.T) {
	store := newQuotaRelayTestStore()
	var retentionSeen bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case core.PathToken:
			clientID, _, _ := request.BasicAuth()
			if clientID == "billing-retention-relay" {
				assertRetentionTokenRequest(t, request)
				writeTokenResponse(writer, "retention-token")
				return
			}
			assertQuotaTokenRequest(t, request)
			writeTokenResponse(writer, "quota-token")
		case core.PathTenantQuotaProjection:
			assertQuotaProjectionRequest(t, request, mustQuotaSourceID(t, "tenant-a"))
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"tenant_id":"tenant-a","revision":2,"applied":true}`)
		case "/api/v1/policies/retention":
			retentionSeen = assertRetentionPolicyRequest(t, writer, request)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	config := quotaRelayTestConfig(server.URL)
	config.Retention = retentionProjectionConfig{
		BaseURL: server.URL, TokenURL: server.URL + core.PathToken,
		ClientID: "billing-retention-relay", ClientSecret: "retention-secret",
		Resource: "audit-governance", HTTPTimeout: time.Second,
	}
	runner, err := buildQuotaRelay(config, store, store)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runner.relay.RunOnce(t.Context())
	if err != nil || result.Delivered != 1 || store.completedRevision != 2 || !retentionSeen {
		t.Fatalf("RunOnce()=%+v error=%v revision=%d retention=%v", result, err, store.completedRevision, retentionSeen)
	}
}

func assertRetentionTokenRequest(t *testing.T, request *http.Request) {
	t.Helper()
	clientID, secret, ok := request.BasicAuth()
	if !ok || clientID != "billing-retention-relay" || secret != "retention-secret" {
		t.Errorf("retention basic auth=%q %q %v", clientID, secret, ok)
	}
	if err := request.ParseForm(); err != nil {
		t.Fatal(err)
	}
	want := url.Values{
		"grant_type": {"client_credentials"}, "scope": {auditgovernance.PlatformRetentionScope},
		"resource": {"audit-governance"},
	}
	if request.PostForm.Encode() != want.Encode() {
		t.Errorf("retention token form=%q want=%q", request.PostForm.Encode(), want.Encode())
	}
}

func writeTokenResponse(writer http.ResponseWriter, token string) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(writer, `{"access_token":"`+token+`","token_type":"Bearer","expires_in":300}`)
}

func assertRetentionPolicyRequest(t *testing.T, writer http.ResponseWriter, request *http.Request) bool {
	t.Helper()
	if request.Method != http.MethodPut || request.Header.Get("Authorization") != "Bearer retention-token" {
		t.Errorf("retention request=%s auth=%q", request.Method, request.Header.Get("Authorization"))
	}
	var policy auditgovernance.RetentionPolicyRecord
	if err := json.NewDecoder(request.Body).Decode(&policy); err != nil {
		t.Error(err)
		return false
	}
	want := auditgovernance.RetentionPolicyRecord{
		TenantID: "tenant-a", HotDays: 7, WarmDays: 30, ArchiveDays: 365,
		RetentionClass: "standard",
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(want)
	if policy != want {
		t.Errorf("retention policy=%+v want=%+v", policy, want)
		return false
	}
	return true
}

func mustQuotaSourceID(t *testing.T, tenantID string) string {
	t.Helper()
	sourceID, err := auditgovernance.TenantSourceID(defaultQuotaSourcePrefix, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return sourceID
}

func assertQuotaTokenRequest(t *testing.T, request *http.Request) {
	t.Helper()
	clientID, secret, ok := request.BasicAuth()
	if !ok || clientID != "billing-quota-relay" || secret != "quota-secret" {
		t.Errorf("token basic auth = %q, %q, %v", clientID, secret, ok)
	}
	if err := request.ParseForm(); err != nil {
		t.Errorf("parse token form: %v", err)
		return
	}
	want := url.Values{
		"grant_type": {"client_credentials"}, "scope": {core.ScopeTenantQuotaProjectionWrite},
		"resource": {"sso-quota-api"},
	}
	if request.PostForm.Encode() != want.Encode() {
		t.Errorf("token form = %q, want %q", request.PostForm.Encode(), want.Encode())
	}
}

func assertQuotaProjectionRequest(t *testing.T, request *http.Request, sourceID string) bool {
	t.Helper()
	if request.Method != http.MethodPut || request.Header.Get("Authorization") != "Bearer quota-token" {
		t.Errorf("projection request = %s auth=%q", request.Method, request.Header.Get("Authorization"))
	}
	var body struct {
		TenantID     string                     `json:"tenant_id"`
		SourceSystem string                     `json:"source_system"`
		Projection   core.TenantQuotaProjection `json:"projection"`
	}
	if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
		t.Errorf("decode projection: %v", err)
		return false
	}
	if body.TenantID != "tenant-a" || body.SourceSystem != sourceID ||
		body.Projection.Revision != 2 || body.Projection.Quota.MaxClients != 3 {
		t.Errorf("projection body = %+v", body)
		return false
	}
	return true
}

func quotaRelayTestConfig(baseURL string) runtimeConfig {
	return runtimeConfig{
		Issuer: baseURL, AllowInsecureLoopback: true,
		Quota: quotaRelayConfig{
			BaseURL: baseURL, TokenURL: baseURL + core.PathToken,
			ClientID: "billing-quota-relay", ClientSecret: "quota-secret",
			SourcePrefix: defaultQuotaSourcePrefix, Scope: core.ScopeTenantQuotaProjectionWrite,
			Resource: "sso-quota-api", RelayOwner: "quota-worker-a",
			HTTPTimeout: time.Second, Lease: 2 * time.Second, BatchSize: 10,
			InitialBackoff: time.Millisecond, MaxBackoff: time.Second,
			PollInterval: time.Millisecond, MaxLag: time.Minute, ErrorPause: time.Millisecond,
		},
	}
}

type quotaRelayTestStore struct {
	mu                sync.Mutex
	event             *tenantcommerce.OutboxEvent
	snapshot          *tenantcommerce.EntitlementSnapshot
	completedRevision uint64
}

func newQuotaRelayTestStore() *quotaRelayTestStore {
	now := time.Now().UTC()
	return &quotaRelayTestStore{
		event: &tenantcommerce.OutboxEvent{
			ID: "event-1", TenantID: "tenant-a", Type: tenantcommerce.EventEntitlementPublished,
			AggregateVersion: 2, Attempts: 1,
		},
		snapshot: &tenantcommerce.EntitlementSnapshot{
			TenantID: "tenant-a", Revision: 2, Active: true,
			Features: map[tenantcommerce.FeatureKey]bool{tenantcommerce.FeatureCoreSSO: true},
			Limits: map[tenantcommerce.LimitKey]tenantcommerce.LimitGrant{
				tenantcommerce.LimitClients:            {Hard: 3},
				tenantcommerce.LimitAuditRetentionDays: {Hard: 365},
			},
			EffectiveAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
		},
	}
}

func TestCommercialRetentionPolicyRejectsMissingOrUnlimitedGrant(t *testing.T) {
	store := newQuotaRelayTestStore()
	delete(store.snapshot.Limits, tenantcommerce.LimitAuditRetentionDays)
	if _, err := commercialRetentionPolicy(store.event, store.snapshot); err == nil {
		t.Fatal("missing retention grant accepted")
	}
	store.snapshot.Limits[tenantcommerce.LimitAuditRetentionDays] = tenantcommerce.LimitGrant{Unlimited: true}
	if _, err := commercialRetentionPolicy(store.event, store.snapshot); err == nil {
		t.Fatal("unlimited retention grant accepted")
	}
}

func (store *quotaRelayTestStore) ClaimQuotaProjectionDeliveries(
	_ context.Context, _ string, _ time.Time, _ time.Duration, _ int,
) ([]*tenantcommerce.OutboxEvent, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.event == nil {
		return nil, nil
	}
	event := store.event
	store.event = nil
	return []*tenantcommerce.OutboxEvent{event}, nil
}

func (store *quotaRelayTestStore) CompleteQuotaProjectionDelivery(
	_ context.Context, _ string, _ string, revision uint64, _ time.Time,
) error {
	store.mu.Lock()
	store.completedRevision = revision
	store.mu.Unlock()
	return nil
}

func (store *quotaRelayTestStore) FailQuotaProjectionDelivery(
	context.Context, string, string, string, time.Time, time.Time,
) error {
	return nil
}

func (store *quotaRelayTestStore) QuotaProjectionDeliveryReady(
	context.Context, time.Time, time.Duration,
) error {
	return nil
}

func (store *quotaRelayTestStore) CurrentEntitlement(
	context.Context, string,
) (*tenantcommerce.EntitlementSnapshot, error) {
	return store.snapshot, nil
}

func TestQuotaRelayRunnerDrainsAfterCancellation(t *testing.T) {
	store := newQuotaRelayTestStore()
	store.event = nil
	runner, err := buildQuotaRelay(quotaRelayTestConfig("http://127.0.0.1:1"), store, store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runner.run(ctx, logDiscard())
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("quota relay did not drain after cancellation")
	}
}

func logDiscard() *log.Logger {
	return log.New(io.Discard, "", 0)
}
