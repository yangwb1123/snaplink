package authenticators

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strconv"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestMemoryPublicKeyStore_IsolatesKeyAndSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	subject := &sso.Subject{
		ID:        "service-1",
		Claims:    map[string]string{"role": "reader"},
		Resources: []string{"https://api.example.test"},
	}
	store := NewMemoryPublicKeyStore()
	store.Register("key-1", publicKey, subject)

	publicKey[0] ^= 0xff
	subject.ID = "attacker"
	subject.Claims["role"] = "admin"
	subject.Resources[0] = "https://evil.example.test"

	resolvedKey, resolved, err := store.Resolve(ctx, "key-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	resolvedKey[0] ^= 0xff
	resolved.ID = "mutated"
	resolved.Claims["role"] = "mutated"
	resolved.Resources[0] = "https://mutated.example.test"

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := ed25519.Sign(privateKey, CanonicalKeyPairMessage("key-1", "nonce-1", timestamp))
	auth := NewKeyPairAuthenticator(store, time.Minute)
	result, err := auth.Authenticate(ctx, &sso.AuthRequest{Credential: map[string]string{
		"key_id": "key-1", "nonce": "nonce-1", "timestamp": timestamp,
		"signature": base64.RawURLEncoding.EncodeToString(signature),
	}})
	if err != nil {
		t.Fatalf("Authenticate after caller mutations: %v", err)
	}
	if result.UserID != "service-1" || result.Attributes["role"] != "reader" {
		t.Fatalf("stored subject changed through alias: %+v", result)
	}

	_, later, err := store.Resolve(ctx, "key-1")
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if later.Resources[0] != "https://api.example.test" {
		t.Fatalf("stored resources changed through alias: %+v", later.Resources)
	}
}
