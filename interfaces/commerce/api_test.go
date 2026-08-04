package commercehttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	tenantcommerce "github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

var commerceTestNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

type recordingObserver struct {
	mu      sync.Mutex
	records []MutationRecord
}

func (o *recordingObserver) ObserveCommerceMutation(_ context.Context, record MutationRecord) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.records = append(o.records, record)
}

func (o *recordingObserver) latest() MutationRecord {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.records[len(o.records)-1]
}

type testEnvironment struct {
	router         *core.StdRouter
	store          *tenantcommerce.MemoryStore
	service        *tenantcommerce.Service
	api            *API
	observer       *recordingObserver
	sourceStore    *usageledger.MemoryStore
	paymentBinding *usageledger.SourceBinding
}

func newTestEnvironment(t *testing.T) *testEnvironment {
	t.Helper()
	store := tenantcommerce.NewMemoryStore()
	sequence := 0
	service, err := tenantcommerce.NewService(store,
		tenantcommerce.WithClock(func() time.Time { return commerceTestNow }),
		tenantcommerce.WithIDGenerator(func(prefix string) (string, error) {
			sequence++
			return fmt.Sprintf("%s_%d", prefix, sequence), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	observer := &recordingObserver{}
	sourceStore, paymentBinding, sources := newPaymentSources(t)
	router := core.NewStdRouter()
	api, err := Mount(router, Deps{
		Commands: service, Queries: store, PaymentSources: sources, Observer: observer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &testEnvironment{
		router: router, store: store, service: service, api: api, observer: observer,
		sourceStore: sourceStore, paymentBinding: paymentBinding,
	}
}

func newPaymentSources(
	t *testing.T,
) (*usageledger.MemoryStore, *usageledger.SourceBinding, *usageledger.SourceResolver) {
	t.Helper()
	store := usageledger.NewMemoryStore()
	binding := &usageledger.SourceBinding{
		ID: "provider-binding", ClientID: "provider-client", TenantID: "tenant-1",
		SourceSystem: "payment:provider-adapter", AllowedDimensions: []usageledger.Dimension{},
		Enabled: true, Revision: 1, CreatedAt: commerceTestNow, UpdatedAt: commerceTestNow,
	}
	if _, err := store.SaveSourceBinding(t.Context(), binding, 0); err != nil {
		t.Fatal(err)
	}
	resolver, err := usageledger.NewSourceResolver(store)
	if err != nil {
		t.Fatal(err)
	}
	return store, binding, resolver
}

func commerceTestPlan(id string, version uint64) *tenantcommerce.Plan {
	return &tenantcommerce.Plan{
		ID: id, Version: version, Name: id, Status: tenantcommerce.PlanActive,
		Interval: tenantcommerce.IntervalMonth,
		Price:    tenantcommerce.Money{Currency: "USD", MinorUnits: 2500},
		Features: map[tenantcommerce.FeatureKey]bool{tenantcommerce.FeatureCoreSSO: true},
		Limits: map[tenantcommerce.LimitKey]tenantcommerce.LimitGrant{
			tenantcommerce.LimitUsers: {Soft: 80, Hard: 100},
		},
	}
}

func serveJSON(t *testing.T, router http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded := []byte{}
	if body != nil {
		var err error
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(encoded))
	request.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func decodeResponse(t *testing.T, response *httptest.ResponseRecorder, target any) {
	t.Helper()
	if err := json.Unmarshal(response.Body.Bytes(), target); err != nil {
		t.Fatalf("decode response %q: %v", response.Body.String(), err)
	}
}

func TestRouteContractsPinAdminScopes(t *testing.T) {
	contracts := RouteContracts()
	if len(contracts) != 18 {
		t.Fatalf("route contracts = %d, want 18", len(contracts))
	}
	for _, contract := range contracts {
		want := ScopeAdminWrite
		switch contract.Path {
		case PathPaymentEventIngest:
			want = ScopePaymentWrite
		case PathPaymentOrderRead:
			want = ScopePaymentOrderRead
		default:
			if contract.Method == http.MethodGet {
				want = ScopeAdminRead
			}
		}
		if contract.RequiredScope != want {
			t.Errorf("%s %s scope = %q, want %q", contract.Method, contract.Path, contract.RequiredScope, want)
		}
	}
}

func TestNewAndMountRejectMissingDependencies(t *testing.T) {
	store := tenantcommerce.NewMemoryStore()
	if _, err := New(Deps{Queries: store}); !errors.Is(err, ErrCommandServiceRequired) {
		t.Fatalf("missing commands error = %v", err)
	}
	if _, err := New(Deps{Commands: (*tenantcommerce.Service)(nil)}); !errors.Is(err, ErrCommandServiceRequired) {
		t.Fatalf("typed nil command error = %v", err)
	}
	service, _ := tenantcommerce.NewService(store)
	api, err := New(Deps{Commands: service, Queries: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRoutes(nil); !errors.Is(err, ErrRouterRequired) {
		t.Fatalf("nil router error = %v", err)
	}
}

func TestCommerceErrorsHaveStableMappings(t *testing.T) {
	tests := []struct {
		err    error
		status int
		code   string
	}{
		{tenantcommerce.ErrPlanNotFound, http.StatusNotFound, ErrorPlanNotFound},
		{tenantcommerce.ErrTenantSubscribed, http.StatusConflict, ErrorTenantSubscribed},
		{tenantcommerce.ErrInvalidLedgerEntry, http.StatusBadRequest, ErrorInvalidLedgerEntry},
		{tenantcommerce.ErrPaymentNotFound, http.StatusNotFound, ErrorPaymentNotFound},
		{tenantcommerce.ErrPaymentEventNotFound, http.StatusNotFound, ErrorPaymentEventNotFound},
		{tenantcommerce.ErrInvalidPayment, http.StatusBadRequest, ErrorInvalidPayment},
		{tenantcommerce.ErrPaymentStateConflict, http.StatusConflict, ErrorPaymentStateConflict},
		{tenantcommerce.ErrWalletFrozen, http.StatusLocked, ErrorWalletFrozen},
		{context.DeadlineExceeded, http.StatusServiceUnavailable, ErrorUnavailable},
		{errors.New("storage unavailable"), http.StatusInternalServerError, core.ErrInternal},
	}
	for _, test := range tests {
		status, code := commerceError(test.err)
		if status != test.status || code != test.code {
			t.Errorf("commerceError(%v) = (%d, %q), want (%d, %q)", test.err, status, code, test.status, test.code)
		}
	}
}
