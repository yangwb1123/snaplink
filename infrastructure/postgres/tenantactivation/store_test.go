package tenantactivation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/activation"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/internal/pgtest"
)

func TestSchemaContract(t *testing.T) {
	for _, fragment := range []string{
		"tenant_activation_codes", "tenant_activation_tickets", "tenant_activation_claims",
		"CHECK ((key_digest <> '') <> (invitation_digest <> ''))",
		"PRIMARY KEY (client_id, product_id, subject)",
	} {
		if !strings.Contains(schema, fragment) {
			t.Errorf("schema missing %q", fragment)
		}
	}
	if MaxVersion() != 1 {
		t.Fatalf("MaxVersion() = %d, want 1", MaxVersion())
	}
}

func TestPostgresActivationRoundTrip(t *testing.T) {
	dialect := postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	db, err := postgresbackend.Open(postgresbackend.Config{DSN: pgtest.Schema(t), Dialect: dialect})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	store, err := NewWithDB(db, dialect, WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewWithDB: %v", err)
	}
	codeID := fmt.Sprintf("code-%d", now.UnixNano())
	if err := store.AddCode(context.Background(), activation.Code{
		ID: codeID, ProductID: "pro", TenantID: "tenant-1", Key: "license-secret",
		Entitlement: &commerceSnapshot,
	}); err != nil {
		t.Fatalf("AddCode: %v", err)
	}
	preparation, err := store.Prepare(context.Background(), activation.PrepareInput{
		ClientID: "spa", ProductID: "pro", LicenseKey: "license-secret",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	claimed, err := store.Claim(context.Background(), activation.ClaimInput{
		Ticket: preparation.Ticket, ClientID: "spa", ProductID: "pro", Subject: "user-1",
	})
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.TenantID != "tenant-1" || claimed.Entitlement == nil || !claimed.Entitlement.Features["core_sso"] {
		t.Fatalf("claimed context = %+v", claimed)
	}
	current, err := store.Current(context.Background(), activation.CurrentInput{
		ClientID: "spa", ProductID: "pro", Subject: "user-1",
	})
	if err != nil || current.TenantID != "tenant-1" {
		t.Fatalf("Current = %+v, err = %v", current, err)
	}
	if _, err := store.Claim(context.Background(), activation.ClaimInput{
		Ticket: preparation.Ticket, ClientID: "spa", ProductID: "pro", Subject: "user-1",
	}); !errors.Is(err, activation.ErrInvalidActivation) {
		t.Fatalf("replayed ticket error = %v, want activation invalid", err)
	}
}

var commerceSnapshot = commerce.EntitlementSnapshot{
	TenantID: "tenant-1",
	Features: map[commerce.FeatureKey]bool{commerce.FeatureCoreSSO: true},
}
