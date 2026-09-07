package authenticators

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestMemoryAPIKeyStore_IsolatesHashAndSubject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	subject := &sso.Subject{
		ID:        "service-1",
		Claims:    map[string]string{"role": "reader"},
		Resources: []string{"https://api.example.test"},
	}
	store := NewMemoryAPIKeyStore()
	store.Register("key-1", "secret-1", subject)

	subject.ID = "attacker"
	subject.Claims["role"] = "admin"
	subject.Resources[0] = "https://evil.example.test"

	hash, resolved, err := store.Resolve(ctx, "key-1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	hash[0] ^= 0xff
	resolved.ID = "mutated"
	resolved.Claims["role"] = "mutated"
	resolved.Resources[0] = "https://mutated.example.test"

	auth := NewAPIKeyAuthenticator(store)
	result, err := auth.Authenticate(ctx, &sso.AuthRequest{Credential: map[string]string{
		"key_id": "key-1", "secret": "secret-1",
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
