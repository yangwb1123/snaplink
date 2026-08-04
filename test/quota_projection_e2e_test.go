package ssotest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/quotaprojection"
	"github.com/yangwb1123/snaplink/shared/core"
)

var quotaProjectionE2ENow = time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)

type quotaProjectionE2EHarness struct {
	service *commerce.Service
	relay   *quotaprojection.Relay
	quota   *memorystoreidentity.MemoryTenantQuotaStore
}

func TestE2ECommerceEntitlementProjectsIntoSSOQuota(t *testing.T) {
	harness := newQuotaProjectionE2EHarness(t)
	publishQuotaProjectionE2EPlan(t, harness.service)
	subscription, _, err := harness.service.CreateSubscription(t.Context(), commerce.CreateSubscriptionCommand{
		ID: "sub-e2e", TenantID: "tenant-e2e", Plan: commerce.PlanRef{ID: "full", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertQuotaProjectionE2EDelivery(t, harness, 1, 4, false)
	_, _, err = harness.service.TransitionSubscription(t.Context(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionCanceled, ExpectedRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertQuotaProjectionE2EDelivery(t, harness, 2, 0, true)
}

func newQuotaProjectionE2EHarness(t *testing.T) *quotaProjectionE2EHarness {
	t.Helper()
	commerceStore := commerce.NewMemoryStore()
	service, err := commerce.NewService(
		commerceStore, commerce.WithClock(func() time.Time { return quotaProjectionE2ENow }),
	)
	if err != nil {
		t.Fatal(err)
	}
	issuer := defaultimpl.NewEd25519JWTIssuer()
	quotaStore := memorystoreidentity.NewMemoryTenantQuotaStore()
	server := sso.NewServer(sso.WithTokenIssuer("jwt", issuer), sso.WithTenantQuotaStore(quotaStore))
	handler := server.Handler()
	projectionHandler, err := sso.NewTenantQuotaProjectionHandler(server, "sso-e2e", []sso.TenantQuotaProjectionSource{{
		ID: "billing-e2e", ClientID: "billing-relay", TenantID: "tenant-e2e",
		SourceSystem: "billing:tenant-e2e", Enabled: true, Revision: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Handle(http.MethodPut, core.PathTenantQuotaProjection, projectionHandler); err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)
	client := newQuotaProjectionE2EClient(t, httpServer, issuer)
	relay, err := quotaprojection.NewRelay(commerceStore, commerceStore, client,
		quotaprojection.RelayConfig{Owner: "relay-e2e"},
		quotaprojection.WithRelayClock(func() time.Time { return quotaProjectionE2ENow }),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &quotaProjectionE2EHarness{service: service, relay: relay, quota: quotaStore}
}

func newQuotaProjectionE2EClient(
	t *testing.T, server *httptest.Server, issuer *defaultimpl.Ed25519JWTIssuer,
) *quotaprojection.HTTPClient {
	t.Helper()
	token, err := issuer.Issue(t.Context(), &core.Subject{
		ID: "billing-relay", ClientID: "billing-relay", Resources: []string{"sso-e2e"},
	}, []string{core.ScopeTenantQuotaProjectionWrite})
	if err != nil {
		t.Fatal(err)
	}
	authorizer := quotaprojection.AuthorizerFunc(func(
		_ context.Context, tenantID string,
	) (quotaprojection.Authorization, error) {
		return quotaprojection.Authorization{
			TenantID: tenantID, SourceSystem: "billing:" + tenantID, BearerToken: token.AccessToken,
		}, nil
	})
	client, err := quotaprojection.NewHTTPClient(quotaprojection.HTTPConfig{
		BaseURL: server.URL, AllowInsecureLoopback: true,
	}, authorizer, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func publishQuotaProjectionE2EPlan(t *testing.T, service *commerce.Service) {
	t.Helper()
	err := service.PublishPlan(t.Context(), &commerce.Plan{
		ID: "full", Version: 1, Name: "Full", Status: commerce.PlanActive,
		Interval: commerce.IntervalMonth, Price: commerce.Money{Currency: "USD", MinorUnits: 4900},
		Features: map[commerce.FeatureKey]bool{commerce.FeatureCoreSSO: true},
		Limits: map[commerce.LimitKey]commerce.LimitGrant{
			commerce.LimitClients: {Hard: 4}, commerce.LimitUsers: {Hard: 0},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertQuotaProjectionE2EDelivery(
	t *testing.T, harness *quotaProjectionE2EHarness,
	revision uint64, maxClients int, inactive bool,
) {
	t.Helper()
	result, err := harness.relay.RunOnce(t.Context())
	if err != nil || result.Delivered != 1 || result.Retried != 0 {
		t.Fatalf("relay result = %+v, %v", result, err)
	}
	projection, err := harness.quota.GetQuotaProjection(t.Context(), "tenant-e2e")
	if err != nil || projection.Revision != revision || projection.Quota.MaxClients != maxClients {
		t.Fatalf("SSO projection = %+v, %v", projection, err)
	}
	if !projection.Quota.UsersLimited || !projection.Quota.ClientsLimited ||
		projection.Quota.SessionsLimited != inactive || projection.Quota.TokenRateLimited != inactive {
		t.Fatalf("hard-zero semantics = %+v", projection.Quota)
	}
}
