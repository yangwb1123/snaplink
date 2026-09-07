package webauthn

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"
)

func TestMemorySessionStore_ClonesCeremonyState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemorySessionStore()
	input := memorySessionFixture()
	if err := store.Put(ctx, "one", input, time.Hour); err != nil {
		t.Fatalf("Put one: %v", err)
	}
	if err := store.Put(ctx, "two", input, time.Hour); err != nil {
		t.Fatalf("Put two: %v", err)
	}
	mutateMemorySession(input, "caller")

	first, err := store.Take(ctx, "one")
	if err != nil {
		t.Fatalf("Take one: %v", err)
	}
	assertMemorySession(t, first)
	mutateMemorySession(first, "returned")

	second, err := store.Take(ctx, "two")
	if err != nil {
		t.Fatalf("Take two: %v", err)
	}
	assertMemorySession(t, second)
}

func memorySessionFixture() *gw.SessionData {
	return &gw.SessionData{
		Challenge: "challenge", RelyingPartyID: "example.com", UserID: []byte("user-id"),
		AllowedCredentialIDs: [][]byte{[]byte("credential-one"), []byte("credential-two")},
		Expires:              time.Unix(123, 0),
		UserVerification:     protocol.VerificationRequired,
		CredParams:           []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType}},
		Extensions: protocol.AuthenticationExtensions{
			"credProps": true,
			"largeBlob": map[string]any{
				"support": "preferred", "blob": []byte("blob"),
				"items": []any{[]byte("item")}, "labels": []string{"label"},
				"flags": map[string]bool{"required": true},
			},
		},
	}
}

func mutateMemorySession(data *gw.SessionData, value string) {
	data.UserID[0] = value[0]
	data.AllowedCredentialIDs[0][0] = value[0]
	data.CredParams[0].Type = protocol.CredentialType(value)
	data.Extensions["credProps"] = false
	nested := data.Extensions["largeBlob"].(map[string]any)
	nested["support"] = value
	nested["blob"].([]byte)[0] = value[0]
	nested["items"].([]any)[0].([]byte)[0] = value[0]
	nested["labels"].([]string)[0] = value
	nested["flags"].(map[string]bool)["required"] = false
}

func assertMemorySession(t *testing.T, data *gw.SessionData) {
	t.Helper()
	if data.Challenge != "challenge" || data.RelyingPartyID != "example.com" || string(data.UserID) != "user-id" {
		t.Fatalf("session identity changed: %+v", data)
	}
	if string(data.AllowedCredentialIDs[0]) != "credential-one" || string(data.AllowedCredentialIDs[1]) != "credential-two" {
		t.Fatalf("allowed credentials changed: %q", data.AllowedCredentialIDs)
	}
	if data.CredParams[0].Type != protocol.PublicKeyCredentialType || data.Extensions["credProps"] != true {
		t.Fatalf("session scalar/map state changed: %+v", data)
	}
	nested := data.Extensions["largeBlob"].(map[string]any)
	if nested["support"] != "preferred" || string(nested["blob"].([]byte)) != "blob" || string(nested["items"].([]any)[0].([]byte)) != "item" || nested["labels"].([]string)[0] != "label" || !nested["flags"].(map[string]bool)["required"] {
		t.Fatalf("nested extension state changed: %#v", nested)
	}
}
