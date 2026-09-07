package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	gw "github.com/go-webauthn/webauthn/webauthn"
)

func TestMemoryUserStore_DefensiveCopiesUserState(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryUserStore()
	handle := []byte("stable-user-handle")
	created, err := store.CreateUserWithHandle(ctx, "alice", "Alice", handle)
	if err != nil {
		t.Fatalf("CreateUserWithHandle: %v", err)
	}
	wantHandle := append([]byte(nil), handle...)
	handle[0] = 'x'
	created.Handle[0] = 'y'

	cred := memoryCredentialFixture()
	if err := store.AddCredential(ctx, "alice", cred); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	discoverable, largeBlob := true, false
	if err := store.SetCredentialExtensions(ctx, "alice", cred.ID, CredentialExtensions{
		Discoverable: &discoverable, LargeBlobSupported: &largeBlob,
	}); err != nil {
		t.Fatalf("SetCredentialExtensions: %v", err)
	}
	mutateMemoryCredential(cred, "caller")
	discoverable, largeBlob = false, true
	assertMemoryUser(t, mustGetUser(t, store), wantHandle, "original")

	got := mustGetUser(t, store)
	mutateMemoryUser(got, "returned")
	byHandle, err := store.GetByHandle(ctx, wantHandle)
	if err != nil {
		t.Fatalf("GetByHandle: %v", err)
	}
	assertMemoryUser(t, byHandle, wantHandle, "original")

	updated := memoryCredentialFixture()
	updated.PublicKey = []byte("updated-public-key")
	if err := store.UpdateCredential(ctx, "alice", updated); err != nil {
		t.Fatalf("UpdateCredential: %v", err)
	}
	mutateMemoryCredential(updated, "Z")
	final := mustGetUser(t, store)
	if !bytes.Equal(final.Credentials[0].PublicKey, []byte("updated-public-key")) {
		t.Fatalf("UpdateCredential input aliased: %q", final.Credentials[0].PublicKey)
	}
}

func memoryCredentialFixture() *gw.Credential {
	return &gw.Credential{
		ID: []byte("credential-id"), PublicKey: []byte("public-key"),
		Transport:     []protocol.AuthenticatorTransport{"usb"},
		Authenticator: gw.Authenticator{AAGUID: []byte("authenticator-guid"), SignCount: 7},
		Attestation: gw.CredentialAttestation{
			ClientDataJSON: []byte("client-data"), ClientDataHash: []byte("client-hash"),
			AuthenticatorData: []byte("authenticator-data"), Object: []byte("attestation-object"),
		},
	}
}

func mutateMemoryCredential(cred *gw.Credential, value string) {
	cred.ID[0] = value[0]
	cred.PublicKey[0] = value[0]
	cred.Transport[0] = protocol.AuthenticatorTransport(value)
	cred.Authenticator.AAGUID[0] = value[0]
	cred.Attestation.ClientDataJSON[0] = value[0]
	cred.Attestation.ClientDataHash[0] = value[0]
	cred.Attestation.AuthenticatorData[0] = value[0]
	cred.Attestation.Object[0] = value[0]
}

func mutateMemoryUser(user *User, value string) {
	user.Handle[0] = value[0]
	mutateMemoryCredential(&user.Credentials[0], value)
	ext := user.CredentialExtensions[base64.RawURLEncoding.EncodeToString([]byte("credential-id"))]
	*ext.Discoverable = false
	*ext.LargeBlobSupported = true
}

func mustGetUser(t *testing.T, store *MemoryUserStore) *User {
	t.Helper()
	user, err := store.GetByName(context.Background(), "alice")
	if err != nil {
		t.Fatalf("GetByName: %v", err)
	}
	return user
}

func assertMemoryUser(t *testing.T, user *User, wantHandle []byte, label string) {
	t.Helper()
	if !bytes.Equal(user.Handle, wantHandle) {
		t.Fatalf("%s handle changed: %q", label, user.Handle)
	}
	cred := user.Credentials[0]
	if !bytes.Equal(cred.ID, []byte("credential-id")) || !bytes.Equal(cred.PublicKey, []byte("public-key")) {
		t.Fatalf("%s credential key material changed: %#v", label, cred)
	}
	if string(cred.Transport[0]) != "usb" || !bytes.Equal(cred.Authenticator.AAGUID, []byte("authenticator-guid")) {
		t.Fatalf("%s authenticator state changed: %#v", label, cred)
	}
	if !bytes.Equal(cred.Attestation.ClientDataJSON, []byte("client-data")) || !bytes.Equal(cred.Attestation.ClientDataHash, []byte("client-hash")) || !bytes.Equal(cred.Attestation.AuthenticatorData, []byte("authenticator-data")) || !bytes.Equal(cred.Attestation.Object, []byte("attestation-object")) {
		t.Fatalf("%s attestation state changed: %#v", label, cred.Attestation)
	}
	ext := user.CredentialExtensions[base64.RawURLEncoding.EncodeToString([]byte("credential-id"))]
	if ext.Discoverable == nil || !*ext.Discoverable || ext.LargeBlobSupported == nil || *ext.LargeBlobSupported {
		t.Fatalf("%s extension state changed: %#v", label, ext)
	}
}
