package oauth

import (
	"testing"

	"github.com/snaplink/sso/core"
)

// validateEnc runs the full DCR validator over a code-flow-valid base
// request so the encryption-metadata rules are what gets exercised.
func validateEnc(t *testing.T, m *DCRMetadata) error {
	t.Helper()
	m.RedirectURIs = []string{"https://rp.example/cb"}
	return ValidateDCRMetadata(m, &DCRPolicy{}, core.SupportedGrants, core.GrantAuthorizationCode)
}

func TestDCREncryption_EncDefaultsWhenAlgSet(t *testing.T) {
	m := &DCRMetadata{IDTokenEncryptedResponseAlg: "RSA-OAEP-256"}
	if err := validateEnc(t, m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.IDTokenEncryptedResponseEnc != DefaultJWEResponseEnc {
		t.Fatalf("enc not defaulted: got %q want %q", m.IDTokenEncryptedResponseEnc, DefaultJWEResponseEnc)
	}
}

func TestDCREncryption_UserinfoEncDefaults(t *testing.T) {
	m := &DCRMetadata{UserinfoEncryptedResponseAlg: "RSA-OAEP-256"}
	if err := validateEnc(t, m); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.UserinfoEncryptedResponseEnc != DefaultJWEResponseEnc {
		t.Fatalf("userinfo enc not defaulted: got %q", m.UserinfoEncryptedResponseEnc)
	}
}

func TestDCREncryption_RejectsUnknownAlg(t *testing.T) {
	m := &DCRMetadata{IDTokenEncryptedResponseAlg: "RSA1_5"}
	if err := validateEnc(t, m); err == nil {
		t.Fatal("expected rejection of unknown alg")
	}
}

func TestDCREncryption_RejectsUnknownEnc(t *testing.T) {
	m := &DCRMetadata{
		UserinfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserinfoEncryptedResponseEnc: "A128CBC-HS256",
	}
	if err := validateEnc(t, m); err == nil {
		t.Fatal("expected rejection of unknown enc")
	}
}

func TestDCREncryption_RejectsEncWithoutAlg(t *testing.T) {
	m := &DCRMetadata{IDTokenEncryptedResponseEnc: "A256GCM"}
	if err := validateEnc(t, m); err == nil {
		t.Fatal("expected rejection of enc without alg")
	}
}

func TestDCREncryption_EmptyIsValid(t *testing.T) {
	m := &DCRMetadata{}
	if err := validateEnc(t, m); err != nil {
		t.Fatalf("empty encryption metadata should be valid: %v", err)
	}
}
