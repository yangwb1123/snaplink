package sso_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

const projectionAudience = "snaplink-sso"

type quotaProjectionFixture struct {
	server *httptest.Server
	issuer *defaultimpl.Ed25519JWTIssuer
	store  *memorystoreidentity.MemoryTenantQuotaStore
	sink   *audit.MemorySink
}

func TestTenantQuotaProjectionUsesCompositeMachineBinding(t *testing.T) {
	fixture := newQuotaProjectionFixture(t)
	token := fixture.machineToken(t, "billing-relay", projectionAudience,
		[]string{core.ScopeTenantQuotaProjectionWrite}, time.Time{})
	status, response, headers := fixture.put(t, token, map[string]any{
		"tenant_id": "tenant-b", "source_system": "billing:tenant-b",
		"projection": projectionBody(3, 12),
	})
	if status != http.StatusOK || response["tenant_id"] != "tenant-b" ||
		response["revision"] != float64(3) || response["applied"] != true {
		t.Fatalf("response = %d, %v", status, response)
	}
	assertNoStore(t, headers)
	projection, err := fixture.store.GetQuotaProjection(t.Context(), "tenant-b")
	if err != nil || projection.Revision != 3 || projection.Quota.MaxClients != 12 {
		t.Fatalf("stored projection = %+v, %v", projection, err)
	}

	status, response, headers = fixture.put(t, token, map[string]any{
		"tenant_id": "tenant-a", "source_system": "billing:tenant-b",
		"projection": projectionBody(4, 99),
	})
	if status != http.StatusForbidden || response["error"] != core.ErrTenantMismatch ||
		!strings.Contains(headers.Get("WWW-Authenticate"), `error="tenant_mismatch"`) {
		t.Fatalf("mismatch = %d, %v, challenge=%q", status, response, headers.Get("WWW-Authenticate"))
	}
	if got, _ := fixture.store.GetQuotaProjection(t.Context(), "tenant-a"); got.Revision != 0 {
		t.Fatalf("untrusted tenant body mutated tenant-a: %+v", got)
	}
	for _, sourceSystem := range []string{"billing:unknown", "billing:disabled"} {
		status, response, _ = fixture.put(t, token, map[string]any{
			"tenant_id": "tenant-a", "source_system": sourceSystem,
			"projection": projectionBody(4, 99),
		})
		if status != http.StatusForbidden || response["error"] != core.ErrInsufficientScope {
			t.Fatalf("source %q = %d, %v", sourceSystem, status, response)
		}
	}
}

func TestTenantQuotaProjectionIsMonotonicAndRejectsEquivocation(t *testing.T) {
	fixture := newQuotaProjectionFixture(t)
	token := fixture.machineToken(t, "billing-relay", projectionAudience,
		[]string{core.ScopeTenantQuotaProjectionWrite}, time.Time{})
	request := map[string]any{
		"tenant_id": "tenant-a", "source_system": "billing:tenant-a",
		"projection": projectionBody(2, 5),
	}
	status, first, _ := fixture.put(t, token, request)
	if status != http.StatusOK || first["applied"] != true {
		t.Fatalf("first = %d, %v", status, first)
	}
	status, replay, _ := fixture.put(t, token, request)
	if status != http.StatusOK || replay["applied"] != false || replay["revision"] != float64(2) {
		t.Fatalf("replay = %d, %v", status, replay)
	}
	request["projection"] = projectionBody(2, 6)
	status, conflict, _ := fixture.put(t, token, request)
	if status != http.StatusConflict || conflict["error"] != core.ErrQuotaProjectionConflict {
		t.Fatalf("equivocation = %d, %v", status, conflict)
	}
	stored, _ := fixture.store.GetQuotaProjection(t.Context(), "tenant-a")
	if stored.Revision != 2 || stored.Quota.MaxClients != 5 {
		t.Fatalf("conflict changed store: %+v", stored)
	}
}

func TestTenantQuotaProjectionRequiresExactClientCredentialsClaims(t *testing.T) {
	fixture := newQuotaProjectionFixture(t)
	body := map[string]any{
		"tenant_id": "tenant-a", "source_system": "billing:tenant-a",
		"projection": projectionBody(1, 1),
	}
	cases := []struct {
		name      string
		token     string
		wantCode  int
		wantError string
	}{
		{name: "invalid bearer", token: "not-a-token", wantCode: 401, wantError: core.ErrInvalidToken},
		{name: "wrong audience", token: fixture.machineToken(t, "billing-relay", "other",
			[]string{core.ScopeTenantQuotaProjectionWrite}, time.Time{}), wantCode: 403, wantError: core.ErrInsufficientScope},
		{name: "missing scope", token: fixture.machineToken(t, "billing-relay", projectionAudience,
			[]string{"read"}, time.Time{}), wantCode: 403, wantError: core.ErrInsufficientScope},
		{name: "interactive shape", token: fixture.machineToken(t, "billing-relay", projectionAudience,
			[]string{core.ScopeTenantQuotaProjectionWrite}, time.Now()), wantCode: 403, wantError: core.ErrInsufficientScope},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			status, response, headers := fixture.put(t, test.token, body)
			if status != test.wantCode || response["error"] != test.wantError {
				t.Fatalf("response = %d, %v", status, response)
			}
			assertNoStore(t, headers)
			if !strings.Contains(headers.Get("WWW-Authenticate"), "Bearer realm=\"tenant-quota-projection\"") {
				t.Fatalf("challenge = %q", headers.Get("WWW-Authenticate"))
			}
		})
	}
}

func TestTenantQuotaProjectionAuditsTrustedMutation(t *testing.T) {
	fixture := newQuotaProjectionFixture(t)
	token := fixture.machineToken(t, "billing-relay", projectionAudience,
		[]string{core.ScopeTenantQuotaProjectionWrite}, time.Time{})
	status, _, _ := fixture.put(t, token, map[string]any{
		"tenant_id": "tenant-a", "source_system": "billing:tenant-a",
		"projection": projectionBody(1, 2),
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	events, err := fixture.sink.Query(t.Context(), audit.Query{
		Type: audit.EventTenantQuotaProjectionApplied, TenantID: "tenant-a",
	})
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %v, %v", events, err)
	}
	event := events[0]
	if event.ClientID != "billing-relay" || event.ActorID != "billing-relay" ||
		event.Outcome != audit.OutcomeSuccess || event.Reason != "applied" ||
		event.Metadata["source_system"] != "billing:tenant-a" {
		t.Fatalf("audit event = %+v", event)
	}
}

func newQuotaProjectionFixture(t *testing.T) *quotaProjectionFixture {
	t.Helper()
	issuer := defaultimpl.NewEd25519JWTIssuer()
	store := memorystoreidentity.NewMemoryTenantQuotaStore()
	sink := audit.NewMemorySink(20)
	server := sso.NewServer(
		sso.WithTokenIssuer("jwt", issuer), sso.WithTenantQuotaStore(store),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	handler := server.Handler()
	projectionHandler, err := sso.NewTenantQuotaProjectionHandler(server, projectionAudience,
		[]sso.TenantQuotaProjectionSource{
			{ID: "binding-a", ClientID: "billing-relay", TenantID: "tenant-a", SourceSystem: "billing:tenant-a", Enabled: true, Revision: 1},
			{ID: "binding-b", ClientID: "billing-relay", TenantID: "tenant-b", SourceSystem: "billing:tenant-b", Enabled: true, Revision: 1},
			{ID: "binding-disabled", ClientID: "billing-relay", TenantID: "tenant-a", SourceSystem: "billing:disabled", Enabled: false, Revision: 1},
		})
	if err != nil {
		t.Fatalf("NewTenantQuotaProjectionHandler: %v", err)
	}
	if err := server.Handle(http.MethodPut, core.PathTenantQuotaProjection, projectionHandler); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)
	return &quotaProjectionFixture{server: httpServer, issuer: issuer, store: store, sink: sink}
}

func (f *quotaProjectionFixture) machineToken(
	t *testing.T, clientID, audience string, scopes []string, authTime time.Time,
) string {
	t.Helper()
	token, err := f.issuer.Issue(t.Context(), &core.Subject{
		ID: clientID, ClientID: clientID, Resources: []string{audience}, AuthTime: authTime,
	}, scopes)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return token.AccessToken
}

func (f *quotaProjectionFixture) put(
	t *testing.T, token string, body map[string]any,
) (int, map[string]any, http.Header) {
	t.Helper()
	wire, _ := json.Marshal(body)
	request, _ := http.NewRequest(http.MethodPut,
		f.server.URL+core.PathTenantQuotaProjection, bytes.NewReader(wire))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := f.server.Client().Do(request)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer response.Body.Close()
	decoded := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response.StatusCode, decoded, response.Header
}

func projectionBody(revision uint64, clients int) core.TenantQuotaProjection {
	return core.TenantQuotaProjection{
		Revision: revision,
		Quota:    core.TenantQuota{MaxClients: clients, ClientsLimited: true},
	}
}

func assertNoStore(t *testing.T, headers http.Header) {
	t.Helper()
	if headers.Get("Cache-Control") != "no-store" || headers.Get("Pragma") != "no-cache" {
		t.Fatalf("cache headers = %v", headers)
	}
}
