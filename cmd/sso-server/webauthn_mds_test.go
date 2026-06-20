package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/metadata"

	"github.com/snaplink/sso/config"
)

// exampleBlobPath reuses the webauthn package's example MDS blob fixture (a
// real JWS signed by metadata.ExampleMDSRoot) — single source of truth, no
// duplicate 16KB fixture.
const exampleBlobPath = "../../domains/authenticators/webauthn/testdata/example_mds_blob.jws"

// writeCustomRootFile writes ExampleMDSRoot (the base64 DER body) to a temp
// file so the cmd CustomRootFile-reading path can be exercised.
func writeCustomRootFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "root.b64")
	if err := os.WriteFile(path, []byte(metadata.ExampleMDSRoot), 0o600); err != nil {
		t.Fatalf("write custom root: %v", err)
	}
	return path
}

// TestBuildWebAuthnMDSProvider_OffByDefault: no source ⇒ nil provider, nil
// error (byte-identical default-off — gw.Config.MDS stays nil).
func TestBuildWebAuthnMDSProvider_OffByDefault(t *testing.T) {
	p, err := buildWebAuthnMDSProvider(config.WebAuthnMDSConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != nil {
		t.Fatal("no MDS source must yield a nil provider")
	}
}

// TestBuildWebAuthnMDSProvider_FromFileWithCustomRoot exercises the full cmd
// path: read the custom root file + load+decode the blob into a provider.
func TestBuildWebAuthnMDSProvider_FromFileWithCustomRoot(t *testing.T) {
	rootPath := writeCustomRootFile(t)
	p, err := buildWebAuthnMDSProvider(config.WebAuthnMDSConfig{
		File:           exampleBlobPath,
		CustomRootFile: rootPath,
	})
	if err != nil {
		t.Fatalf("buildWebAuthnMDSProvider: %v", err)
	}
	if p == nil {
		t.Fatal("expected a provider")
	}
	if !p.GetValidateTrustAnchor(t.Context()) {
		t.Fatal("provider should validate the trust anchor (adversary-resistance)")
	}
}

// TestBuildWebAuthnMDSProvider_WrongRootFailsLoud: a configured source with
// the WRONG root (default FIDO production root vs the test-root-signed blob)
// fails loud — we never silently downgrade to no-MDS.
func TestBuildWebAuthnMDSProvider_WrongRootFailsLoud(t *testing.T) {
	_, err := buildWebAuthnMDSProvider(config.WebAuthnMDSConfig{File: exampleBlobPath})
	if err == nil {
		t.Fatal("expected wrong-root blob to fail loud")
	}
}

// TestBuildWebAuthnMDSProvider_StrayCustomRootFailsLoud: a custom_root_file
// with no blob source is a misconfiguration and must fail loud, not no-op.
func TestBuildWebAuthnMDSProvider_StrayCustomRootFailsLoud(t *testing.T) {
	rootPath := writeCustomRootFile(t)
	_, err := buildWebAuthnMDSProvider(config.WebAuthnMDSConfig{CustomRootFile: rootPath})
	if err == nil || !strings.Contains(err.Error(), "custom_root_file is set but neither") {
		t.Fatalf("expected stray-custom-root error, got: %v", err)
	}
}

// TestBuildWebAuthnMDSProvider_MissingCustomRootFailsLoud: a configured blob
// source pointing at a missing custom root file fails loud.
func TestBuildWebAuthnMDSProvider_MissingCustomRootFailsLoud(t *testing.T) {
	_, err := buildWebAuthnMDSProvider(config.WebAuthnMDSConfig{
		File:           exampleBlobPath,
		CustomRootFile: "/nonexistent/root.b64",
	})
	if err == nil || !strings.Contains(err.Error(), "read custom_root_file") {
		t.Fatalf("expected missing-custom-root error, got: %v", err)
	}
}

// TestBuildWebAuthnMDSProvider_EmptyCustomRootFailsLoud: an empty custom root
// file fails loud.
func TestBuildWebAuthnMDSProvider_EmptyCustomRootFailsLoud(t *testing.T) {
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "empty.b64")
	if err := os.WriteFile(rootPath, nil, 0o600); err != nil {
		t.Fatalf("write empty root: %v", err)
	}
	_, err := buildWebAuthnMDSProvider(config.WebAuthnMDSConfig{
		File:           exampleBlobPath,
		CustomRootFile: rootPath,
	})
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty-custom-root error, got: %v", err)
	}
}

// TestBuildWebAuthnHelper_MDSWiresThrough proves the full cmd helper build
// reaches gw.Config.MDS when an MDS source is configured, and leaves it nil
// when not (the default-off byte-identical proof at the cmd layer).
func TestBuildWebAuthnHelper_MDSWiresThrough(t *testing.T) {
	rootPath := writeCustomRootFile(t)

	// Without MDS → gw.Config.MDS nil.
	off, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper (no mds): %v", err)
	}
	if off.MDSEnabled() {
		t.Fatal("no MDS source must leave the helper without MDS (gw.Config.MDS nil)")
	}

	// With MDS → gw.Config.MDS set.
	on, _, _, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
		Attestation: config.WebAuthnAttestationConfig{
			MDS: config.WebAuthnMDSConfig{
				File:           exampleBlobPath,
				CustomRootFile: rootPath,
			},
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper (mds): %v", err)
	}
	if !on.MDSEnabled() {
		t.Fatal("configured MDS source must reach gw.Config.MDS")
	}
}
