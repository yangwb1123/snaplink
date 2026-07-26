package sqlite

import (
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

func TestHashClientSecretField(t *testing.T) {
	// Empty value should return empty
	result, err := hashClientSecretField("", "test_field")
	if err != nil {
		t.Fatalf("hash empty: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty result for empty input, got %s", result)
	}

	// Non-empty value should be bcrypt-hashed
	result, err = hashClientSecretField("my-secret", "test_field")
	if err != nil {
		t.Fatalf("hash secret: %v", err)
	}
	if result == "my-secret" {
		t.Error("expected hash, got plaintext")
	}
	if !isBcryptHash(result) {
		t.Errorf("expected bcrypt hash prefix")
	}
}

func TestClientWriteArgs(t *testing.T) {
	client := &sso.Client{
		ID: "test-id",
	}

	args, err := clientWriteArgs(client, "provided-secret", "provided-rat")
	if err != nil {
		t.Fatalf("clientWriteArgs: %v", err)
	}
	if len(args) == 0 {
		t.Error("expected non-empty args")
	}

	// Test with client that has its own secret
	clientWithSecret := &sso.Client{
		ID:     "id-with-secret",
		Secret: "my-secret",
	}
	args2, err := clientWriteArgs(clientWithSecret, "", "")
	if err != nil {
		t.Fatalf("clientWriteArgs with secret: %v", err)
	}
	if len(args2) == 0 {
		t.Error("expected non-empty args")
	}
}

func TestClientWritePrep(t *testing.T) {
	client := &sso.Client{
		ID: "prep-test",
	}
	args, err := clientWritePrep(client)
	if err != nil {
		t.Fatalf("clientWritePrep: %v", err)
	}
	if len(args) == 0 {
		t.Error("expected non-empty args")
	}
}

func TestClientScanRowScalars(t *testing.T) {
	r := &clientScanRow{
		activeInt:         1,
		requirePKCEInt:    1,
		requireSROInt:     0,
		secret:            "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyhashdu",
		rat:               "$2a$10$dummyhashdummyhashdummyhashdummyhashdummyhashdu",
	}
	r.scalars()

	if !r.c.Active {
		t.Error("expected Active=true")
	}
	if !r.c.RequirePKCE {
		t.Error("expected RequirePKCE=true")
	}
	if r.c.RequireSignedRequestObject {
		t.Error("expected RequireSignedRequestObject=false")
	}
}

func TestClientScanRowJsonFieldsEmpty(t *testing.T) {
	r := &clientScanRow{}
	err := r.jsonFields()
	if err != nil {
		t.Fatalf("jsonFields empty: %v", err)
	}
}

func TestUnmarshalClientJSON(t *testing.T) {
	t.Run("valid json", func(t *testing.T) {
		var dst []string
		err := unmarshalClientJSON(`["a", "b", "c"]`, &dst, "test_field")
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(dst) != 3 {
			t.Errorf("expected 3 items, got %d", len(dst))
		}
	})

	t.Run("empty json", func(t *testing.T) {
		var dst []string
		err := unmarshalClientJSON("", &dst, "test_field")
		if err != nil {
			t.Fatalf("unmarshal empty: %v", err)
		}
		// Empty JSON leaves dst as nil (zero value) — this is fine
		_ = dst
	})

	t.Run("invalid json", func(t *testing.T) {
		var dst []string
		err := unmarshalClientJSON("{invalid}", &dst, "test_field")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("object instead of array", func(t *testing.T) {
		var dst []string
		err := unmarshalClientJSON(`{"key": "value"}`, &dst, "test_field")
		// Should not error but result might be empty
		_ = err
	})
}

func TestUnmarshalClientJSONMap(t *testing.T) {
	t.Run("valid map", func(t *testing.T) {
		var dst map[string]string
		err := unmarshalClientJSON(`{"key1": "val1", "key2": "val2"}`, &dst, "test_field")
		if err != nil {
			t.Fatalf("unmarshal map: %v", err)
		}
		if len(dst) != 2 {
			t.Errorf("expected 2 entries, got %d", len(dst))
		}
	})

	t.Run("null map", func(t *testing.T) {
		var dst map[string]string
		err := unmarshalClientJSON("null", &dst, "test_field")
		if err != nil {
			t.Fatalf("unmarshal null: %v", err)
		}
	})
}

func BenchmarkClientWriteArgs(b *testing.B) {
	client := &sso.Client{
		ID:           "bench-client",
		RedirectURIs: []string{"https://app.example.com/callback"},
		AllowedScopes: []string{"openid", "profile"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = clientWriteArgs(client, "secret", "rat")
	}
}
