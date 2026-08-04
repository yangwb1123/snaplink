package tenantcommerce

import (
	"context"
	"errors"
	"os"
	"testing"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	postgresledger "github.com/yangwb1123/snaplink/infrastructure/postgres/usageledger"
)

func TestPostgresPaymentSourceRevisionIsFencedInTransaction(t *testing.T) {
	store := integrationStore(t)
	dialect := postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	sources, err := postgresledger.NewWithDB(store.db, dialect)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(t.Context(), `TRUNCATE usage_source_bindings`); err != nil {
		t.Fatal(err)
	}
	binding := paymentBindingFixture()
	if _, err := sources.SaveSourceBinding(t.Context(), binding, 0); err != nil {
		t.Fatal(err)
	}
	service := integrationService(t, store)
	order, err := service.CreateTopUpOrder(t.Context(), commerce.CreateTopUpCommand{
		ID: "pay-bound", TenantID: binding.TenantID, Provider: "testpay",
		ProviderOrderID: "provider-bound", Currency: "USD", AmountMinor: 500,
		IdempotencyKey: "checkout-bound",
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled := *binding
	disabled.Enabled, disabled.Revision = false, 2
	disabled.UpdatedAt = integrationNow.Add(1)
	if _, err := sources.SaveSourceBinding(t.Context(), &disabled, 1); err != nil {
		t.Fatal(err)
	}
	event := paymentEvent(order, "capture-bound", commerce.PaymentCaptured, 500)
	_, _, _, err = service.ApplyAuthorizedPaymentEvent(t.Context(), paymentEvidence(binding), event)
	if !errors.Is(err, commerce.ErrPaymentSourceUnauthorized) {
		t.Fatalf("stale payment source error = %v", err)
	}
	assertPaymentStillPending(t, store, order.ID)
	reenabled := disabled
	reenabled.Enabled, reenabled.Revision = true, 3
	reenabled.UpdatedAt = integrationNow.Add(2)
	if _, err := sources.SaveSourceBinding(t.Context(), &reenabled, 2); err != nil {
		t.Fatal(err)
	}
	_, _, wallet, err := service.ApplyAuthorizedPaymentEvent(t.Context(), paymentEvidence(&reenabled), event)
	if err != nil || wallet.BalanceMinor != 500 {
		t.Fatalf("current payment source result wallet=%+v err=%v", wallet, err)
	}
}

func paymentBindingFixture() *ledger.SourceBinding {
	return &ledger.SourceBinding{
		ID: "payment-binding", ClientID: "testpay-adapter", TenantID: "tenant-bound",
		SourceSystem: "payment:testpay", AllowedDimensions: []ledger.Dimension{}, Enabled: true,
		Revision: 1, CreatedAt: integrationNow, UpdatedAt: integrationNow,
	}
}

func paymentEvidence(binding *ledger.SourceBinding) commerce.PaymentSourceEvidence {
	return commerce.PaymentSourceEvidence{
		BindingID: binding.ID, ClientID: binding.ClientID, TenantID: binding.TenantID,
		SourceSystem: binding.SourceSystem, Revision: binding.Revision,
	}
}

func assertPaymentStillPending(t *testing.T, store *Store, orderID string) {
	t.Helper()
	order, err := store.GetPaymentOrder(context.Background(), orderID)
	if err != nil || order.Status != commerce.PaymentPending {
		t.Fatalf("rejected binding mutated order: %+v err=%v", order, err)
	}
	events, err := store.ListPaymentEvents(context.Background(), orderID)
	if err != nil || len(events) != 0 {
		t.Fatalf("rejected binding wrote payment events: %+v err=%v", events, err)
	}
}
