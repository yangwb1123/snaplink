package serverbuildstore

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/tenant/activation"
)

func TestBuildActivationStoreSeedsMemoryCode(t *testing.T) {
	store, err := BuildActivationStore(config.ActivationConfig{
		Backend: "memory",
		Codes: []config.ActivationCodeConfig{{
			ID: "license-1", ProductID: "pro", TenantID: "tenant-1", LicenseKey: "paid-key",
		}},
	})
	if err != nil {
		t.Fatalf("BuildActivationStore: %v", err)
	}
	preparation, err := store.Prepare(context.Background(), activation.PrepareInput{
		ClientID: "spa", ProductID: "pro", LicenseKey: "paid-key",
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	contextValue, err := store.Claim(context.Background(), activation.ClaimInput{
		Ticket: preparation.Ticket, ClientID: "spa", ProductID: "pro", Subject: "user-1",
	})
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if contextValue.TenantID != "tenant-1" {
		t.Fatalf("tenant_id = %q, want tenant-1", contextValue.TenantID)
	}
}

func TestBuildActivationStoreDisabledAndUnknown(t *testing.T) {
	store, err := BuildActivationStore(config.ActivationConfig{})
	if err != nil || store != nil {
		t.Fatalf("disabled store = %v, err = %v; want nil, nil", store, err)
	}
	if _, err := BuildActivationStore(config.ActivationConfig{Backend: "postgres"}); err == nil {
		t.Fatal("unknown activation backend accepted")
	}
}
