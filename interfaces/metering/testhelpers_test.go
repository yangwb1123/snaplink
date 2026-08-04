package meteringhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
)

var interfaceTestNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

type usageStub struct {
	mu              sync.Mutex
	appendEvidence  usageledger.SourceBindingEvidence
	appendCommand   usageledger.UsageCommand
	reserveEvidence usageledger.SourceBindingEvidence
	reserveCommand  usageledger.ReservationCommand
	commitEvidence  usageledger.SourceBindingEvidence
	commitID        string
	commitCommand   usageledger.AuthorizedCommitCommand
	releaseEvidence usageledger.SourceBindingEvidence
	releaseID       string
	appendError     error
	reserveError    error
	commitError     error
	releaseError    error
	appendCalls     int
}

func (s *usageStub) AppendAuthorized(
	_ context.Context, evidence usageledger.SourceBindingEvidence, command usageledger.UsageCommand,
) (*usageledger.UsageFact, *usageledger.Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appendCalls++
	s.appendEvidence = evidence
	s.appendCommand = command
	if s.appendError != nil {
		return nil, nil, s.appendError
	}
	command.TenantID, command.SourceSystem = evidence.TenantID, evidence.SourceSystem
	return factFromCommand(command), &usageledger.Counter{TenantID: evidence.TenantID}, nil
}

func (s *usageStub) ReserveAuthorized(
	_ context.Context, evidence usageledger.SourceBindingEvidence, command usageledger.ReservationCommand,
) (*usageledger.Reservation, *usageledger.Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reserveEvidence = evidence
	s.reserveCommand = command
	if s.reserveError != nil {
		return nil, nil, s.reserveError
	}
	command.TenantID, command.SourceSystem = evidence.TenantID, evidence.SourceSystem
	return reservationFromCommand(command), &usageledger.Counter{TenantID: evidence.TenantID}, nil
}

func (s *usageStub) CommitAuthorized(
	_ context.Context, evidence usageledger.SourceBindingEvidence, reservationID string,
	command usageledger.AuthorizedCommitCommand,
) (*usageledger.Reservation, *usageledger.Counter, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commitEvidence, s.commitID, s.commitCommand = evidence, reservationID, command
	if s.commitError != nil {
		return nil, nil, s.commitError
	}
	return &usageledger.Reservation{
		ID: reservationID, TenantID: evidence.TenantID, SourceSystem: evidence.SourceSystem,
		Dimension: "messages_per_month", Status: usageledger.ReservationCommitted,
	}, &usageledger.Counter{TenantID: evidence.TenantID}, nil
}

func (s *usageStub) ReleaseAuthorized(
	_ context.Context, evidence usageledger.SourceBindingEvidence, reservationID string,
) (*usageledger.Reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.releaseEvidence, s.releaseID = evidence, reservationID
	if s.releaseError != nil {
		return nil, s.releaseError
	}
	return &usageledger.Reservation{
		ID: reservationID, TenantID: evidence.TenantID, SourceSystem: evidence.SourceSystem,
		Dimension: "messages_per_month", Status: usageledger.ReservationReleased,
	}, nil
}

func factFromCommand(command usageledger.UsageCommand) *usageledger.UsageFact {
	id := command.ID
	if id == "" {
		id = "usage-generated"
	}
	return &usageledger.UsageFact{
		ID: id, TenantID: command.TenantID, SourceSystem: command.SourceSystem,
		Dimension: command.Dimension, Quantity: command.Quantity, Period: command.Period,
		IdempotencyKey: command.IdempotencyKey, OccurredAt: command.OccurredAt,
	}
}

func reservationFromCommand(command usageledger.ReservationCommand) *usageledger.Reservation {
	id := command.ID
	if id == "" {
		id = "reservation-generated"
	}
	return &usageledger.Reservation{
		ID: id, TenantID: command.TenantID, SourceSystem: command.SourceSystem,
		Dimension: command.Dimension, Quantity: command.Quantity, Period: command.Period,
		IdempotencyKey: command.IdempotencyKey, Status: usageledger.ReservationPending,
	}
}

type sourceResolverStub struct {
	binding *usageledger.SourceBinding
	err     error
	resolve func(context.Context, string) (*usageledger.SourceBinding, error)
}

func (s sourceResolverStub) Resolve(ctx context.Context, clientID string) (*usageledger.SourceBinding, error) {
	if s.resolve != nil {
		return s.resolve(ctx, clientID)
	}
	return s.binding, s.err
}

type entitlementReaderStub struct {
	mu       sync.Mutex
	tenantID string
	snapshot *commerce.EntitlementSnapshot
	err      error
}

func (s *entitlementReaderStub) CurrentEntitlement(
	_ context.Context, tenantID string,
) (*commerce.EntitlementSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenantID = tenantID
	return s.snapshot, s.err
}

func defaultBinding() *usageledger.SourceBinding {
	return &usageledger.SourceBinding{
		ID: "source-1", ClientID: "aero-im-machine", TenantID: "tenant-1",
		SourceSystem: "aero-im", AllowedDimensions: []usageledger.Dimension{"messages_per_month"},
		Enabled: true, Revision: 1, CreatedAt: interfaceTestNow, UpdatedAt: interfaceTestNow,
	}
}

func defaultClaims(scope string) *rs.Claims {
	return &rs.Claims{Subject: "aero-im-machine", ClientID: "aero-im-machine", Scope: scope}
}

func defaultDeps() (Deps, *usageStub, *entitlementReaderStub) {
	usage := &usageStub{}
	entitlements := &entitlementReaderStub{snapshot: &commerce.EntitlementSnapshot{
		TenantID: "tenant-1", Active: true, Revision: 1,
		EffectiveAt: interfaceTestNow.Add(-time.Hour), ExpiresAt: interfaceTestNow.Add(time.Hour),
	}}
	return Deps{
		Usage: usage, Entitlements: entitlements,
		Sources: sourceResolverStub{binding: defaultBinding()},
	}, usage, entitlements
}

func testRouter(t *testing.T, deps Deps) core.Router {
	t.Helper()
	router := core.NewStdRouter()
	api, err := New(deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterRoutes(router); err != nil {
		t.Fatal(err)
	}
	return router
}

func serveRequest(
	router core.Router, claims *rs.Claims, method, path, body string, headers map[string]string,
) *httptest.ResponseRecorder {
	var reader io.Reader = http.NoBody
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, path, reader)
	if claims != nil {
		request = request.WithContext(rs.NewContext(request.Context(), claims))
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func jsonHeaders(key string) map[string]string {
	return map[string]string{core.HeaderContentType: core.ContentTypeJSON, headerIdempotency: key}
}

func periodJSON() string {
	period := usageledger.MonthlyPeriod(interfaceTestNow)
	return `{"start":"` + period.Start.Format(time.RFC3339) + `","end":"` +
		period.End.Format(time.RFC3339) + `"}`
}
