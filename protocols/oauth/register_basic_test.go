package oauth

import (
	"testing"
)

func TestGenerateClientID(t *testing.T) {
	t.Parallel()

	id, err := GenerateClientID()
	if err != nil {
		t.Fatalf("GenerateClientID() error: %v", err)
	}
	if id == "" {
		t.Fatal("GenerateClientID() returned empty string")
	}
	// 18 bytes base64url = ~24 chars
	if len(id) < 20 || len(id) > 30 {
		t.Errorf("unexpected client_id length: %d", len(id))
	}
	// Two IDs should differ
	id2, _ := GenerateClientID()
	if id == id2 {
		t.Error("GenerateClientID() returned same value twice")
	}
}

func TestGenerateClientSecret(t *testing.T) {
	t.Parallel()

	secret, err := GenerateClientSecret()
	if err != nil {
		t.Fatalf("GenerateClientSecret() error: %v", err)
	}
	if secret == "" {
		t.Fatal("GenerateClientSecret() returned empty string")
	}
	// 32 bytes base64url = ~43 chars
	if len(secret) < 40 || len(secret) > 48 {
		t.Errorf("unexpected client_secret length: %d", len(secret))
	}
	// Two secrets should differ
	secret2, _ := GenerateClientSecret()
	if secret == secret2 {
		t.Error("GenerateClientSecret() returned same value twice")
	}
}
