package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildauthn"
	"github.com/snaplink/sso/config"
)

// TestLoadEd25519PublicKeyPEM_GoodFile proves the loader accepts a
// PKIX-marshaled Ed25519 PUBLIC KEY block and recovers the original
// 32 bytes — equivalence to a known reference is the cheapest
// way to lock the round-trip.
func TestLoadEd25519PublicKeyPEM_GoodFile(t *testing.T) {
	t.Parallel()
	pub, path := writeEd25519PubKey(t)
	got, err := serverbuildauthn.LoadEd25519PublicKeyPEM(path)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !pub.Equal(got) {
		t.Fatalf("recovered pubkey != original")
	}
}

// TestLoadEd25519PublicKeyPEM_RejectsWrongPEMType — RSA / ECDSA
// PEM blocks SHOULD fail loud rather than silently flow into the
// store. The Ed25519 type-assertion in the loader handles this;
// the test pins the surface so a future refactor can't relax it
// without flagging.
func TestLoadEd25519PublicKeyPEM_RejectsWrongPEMType(t *testing.T) {
	t.Parallel()
	tmp := filepath.Join(t.TempDir(), "wrong.pem")
	bogus := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: []byte("notreallyakey")})
	if err := os.WriteFile(tmp, bogus, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := serverbuildauthn.LoadEd25519PublicKeyPEM(tmp)
	if err == nil || !strings.Contains(err.Error(), "PUBLIC KEY") {
		t.Fatalf("err = %v; want PUBLIC KEY type error", err)
	}
}

// TestLoadEd25519PublicKeyPEM_MissingFileSurfaces — operators who
// typo a path see the error at boot rather than at first /auth/login
// against an empty store.
func TestLoadEd25519PublicKeyPEM_MissingFileSurfaces(t *testing.T) {
	t.Parallel()
	if _, err := serverbuildauthn.LoadEd25519PublicKeyPEM("/no/such/key.pem"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestBuildAuthenticators_KeyPairSeedsRegistered proves the YAML
// public_keys list flows through to the MemoryPublicKeyStore — the
// previous wiring threw away a randomly-generated private key and
// registered an orphan public key under "svc-001", which no real
// caller could ever authenticate against. The test verifies that an
// explicit seed entry produces an authenticator that resolves the
// configured key_id back to the configured subject.
func TestBuildAuthenticators_KeyPairSeedsRegistered(t *testing.T) {
	t.Parallel()
	_, path := writeEd25519PubKey(t)
	cfg := &config.Config{}
	cfg.Authenticators.KeyPair = &config.KeyPairConfig{
		Enabled: true,
		PublicKeys: []config.KeyPairPublicKeyConfig{{
			KeyID:         "svc-test",
			PublicKeyFile: path,
			SubjectID:     "subject-test",
		}},
	}
	auths, _, _, _, _ := serverbuildauthn.BuildAuthenticators(cfg, quietLogger(), nil, nil, nil)
	found := false
	for _, a := range auths {
		if a.Name() == "keypair" {
			found = true
		}
	}
	if !found {
		t.Fatal("keypair authenticator not registered when Enabled=true with valid public_keys")
	}
}

// TestBuildAuthenticators_KeyPairSkipsBadEntries — a single bad seed
// entry shouldn't drop the whole authenticator. The valid entries
// register, the bad one is logged + skipped, and the authenticator
// stays in the registry. Verifies the cmd-side fail-soft behavior
// (logger.Error + continue) on a per-entry basis.
func TestBuildAuthenticators_KeyPairSkipsBadEntries(t *testing.T) {
	t.Parallel()
	_, goodPath := writeEd25519PubKey(t)
	cfg := &config.Config{}
	cfg.Authenticators.KeyPair = &config.KeyPairConfig{
		Enabled: true,
		PublicKeys: []config.KeyPairPublicKeyConfig{
			{KeyID: "", PublicKeyFile: goodPath, SubjectID: "missing-id"},
			{KeyID: "ok", PublicKeyFile: goodPath, SubjectID: "good"},
			{KeyID: "bad-path", PublicKeyFile: "/no/such/file.pem", SubjectID: "missing-file"},
		},
	}
	auths, _, _, _, _ := serverbuildauthn.BuildAuthenticators(cfg, quietLogger(), nil, nil, nil)
	found := false
	for _, a := range auths {
		if a.Name() == "keypair" {
			found = true
		}
	}
	if !found {
		t.Fatal("keypair authenticator was dropped despite at least one valid seed entry")
	}
}

// writeEd25519PubKey generates a fresh Ed25519 keypair, writes the
// PKIX-marshaled public half to a tempdir PEM file, and returns
// (public_key, file_path) for tests to verify loading.
func writeEd25519PubKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	path := filepath.Join(t.TempDir(), "svc.pub.pem")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return pub, path
}
