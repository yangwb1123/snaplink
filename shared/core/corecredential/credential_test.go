package corecredential

import (
	"context"
	"testing"
	"time"
)

func TestCredentialTypeConstants(t *testing.T) {
	if CredentialTypeOAuthClientSecret != "oauth_client_secret" {
		t.Errorf("expected 'oauth_client_secret', got %q", CredentialTypeOAuthClientSecret)
	}
	if CredentialTypeWebhookHMAC != "webhook_hmac" {
		t.Errorf("expected 'webhook_hmac', got %q", CredentialTypeWebhookHMAC)
	}
	if CredentialTypeJWEDecryption != "jwe_decryption" {
		t.Errorf("expected 'jwe_decryption', got %q", CredentialTypeJWEDecryption)
	}
}

func TestCredentialStatusConstants(t *testing.T) {
	if CredentialStatusActive != "active" {
		t.Errorf("expected 'active', got %q", CredentialStatusActive)
	}
	if CredentialStatusRetiring != "retiring" {
		t.Errorf("expected 'retiring', got %q", CredentialStatusRetiring)
	}
	if CredentialStatusRetired != "retired" {
		t.Errorf("expected 'retired', got %q", CredentialStatusRetired)
	}
	if CredentialStatusCompromised != "compromised" {
		t.Errorf("expected 'compromised', got %q", CredentialStatusCompromised)
	}
}

func TestNopDependentPartyNotifier(t *testing.T) {
	nop := NopDependentPartyNotifier{}
	if err := nop.Notify(context.Background(), RotationNotice{}); err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestRotationNoticeFields(t *testing.T) {
	now := time.Now()
	notice := RotationNotice{
		Type: CredentialTypeOAuthClientSecret,
		NewMeta: CredentialMeta{
			ID:        "v2",
			Type:      CredentialTypeOAuthClientSecret,
			Version:   2,
			Status:    CredentialStatusActive,
			CreatedAt: now,
		},
		Compromised: true,
		Reason:     "test compromise",
	}

	if notice.Type != CredentialTypeOAuthClientSecret {
		t.Errorf("expected OAuth client secret type, got %q", notice.Type)
	}
	if !notice.Compromised {
		t.Error("expected Compromised=true")
	}
	if notice.Reason != "test compromise" {
		t.Errorf("expected 'test compromise', got %q", notice.Reason)
	}
	if notice.NewMeta.Version != 2 {
		t.Errorf("expected version 2, got %d", notice.NewMeta.Version)
	}
}

func TestDependencyConstants(t *testing.T) {
	if DependencyJWKS != "jwks" {
		t.Errorf("expected 'jwks', got %q", DependencyJWKS)
	}
	if DependencySAMLMetadata != "saml_metadata" {
		t.Errorf("expected 'saml_metadata', got %q", DependencySAMLMetadata)
	}
	if DependencyWebhookReceivers != "webhook_receivers" {
		t.Errorf("expected 'webhook_receivers', got %q", DependencyWebhookReceivers)
	}
}

func TestCredentialMetaDefault(t *testing.T) {
	meta := CredentialMeta{}
	if meta.ID != "" {
		t.Errorf("expected empty ID, got %q", meta.ID)
	}
	if meta.Status != "" {
		t.Errorf("expected empty Status, got %q", meta.Status)
	}
	if meta.Version != 0 {
		t.Errorf("expected zero Version, got %d", meta.Version)
	}
}

func TestCredentialMetaFields(t *testing.T) {
	now := time.Now()
	meta := CredentialMeta{
		ID:        "key-1",
		Type:      CredentialTypeJWEDecryption,
		Version:   5,
		Status:    CredentialStatusActive,
		CreatedAt: now,
	}

	if meta.ID != "key-1" {
		t.Errorf("expected 'key-1', got %q", meta.ID)
	}
	if meta.Type != CredentialTypeJWEDecryption {
		t.Errorf("expected JWE decryption type, got %q", meta.Type)
	}
	if meta.Version != 5 {
		t.Errorf("expected version 5, got %d", meta.Version)
	}
}

func TestErrCredentialNotFound(t *testing.T) {
	if ErrCredentialNotFound == nil {
		t.Fatal("expected non-nil error")
	}
}
