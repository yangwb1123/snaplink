package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
)

// These cover the cmd boot-error guards added for the OpenID Federation 1.0
// §3.1.2 federation-resolved trust-mark issuer path (slice 4c): the opt-in flag
// must have a root of trust (a configured anchor), and a required type must have
// SOME authorized-issuer source (configured issuers OR the resolved path).
// buildFederationConfig is package-private; this test is package main.

// writeAnchorJWKSFile writes a minimal valid single-key JWKS document (a real
// Ed25519 public key) to a temp file and returns its path — enough for the
// anchor-load path to succeed so the guard logic (not the JWKS load) is what's
// under test.
func writeAnchorJWKSFile(t *testing.T) string {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://anchor.fed.test"))
	keys, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	doc, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	path := filepath.Join(t.TempDir(), "anchor-jwks.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	return path
}

// Flag ON with NO trust anchors -> boot error (the anchor is the root of trust
// that authorizes a resolved issuer; without one the path is inert).
func TestBuildFederationConfig_ResolvedFlagWithoutAnchors_BootError(t *testing.T) {
	cfg := config.FederationConfig{
		RequiredTrustMarkTypes:                  []string{"https://fed.test/tm/certified"},
		AllowFederationResolvedTrustMarkIssuers: true,
		// No TrustAnchors.
	}
	_, err := buildFederationConfig(cfg)
	if err == nil {
		t.Fatal("buildFederationConfig(flag on, no anchors) = nil, want a boot error")
	}
	if !strings.Contains(err.Error(), "trust_anchors") {
		t.Errorf("error = %q, want it to name the missing trust_anchors", err)
	}
}

// A required type with NO configured issuers AND the resolved flag OFF -> boot
// error (no authorized-issuer source at all would admit no RP).
func TestBuildFederationConfig_RequiredTypeNoIssuerSource_BootError(t *testing.T) {
	cfg := config.FederationConfig{
		RequiredTrustMarkTypes:                  []string{"https://fed.test/tm/certified"},
		AllowFederationResolvedTrustMarkIssuers: false,
		// No TrustMarkIssuers, flag off.
	}
	_, err := buildFederationConfig(cfg)
	if err == nil {
		t.Fatal("buildFederationConfig(required type, no issuer source) = nil, want a boot error")
	}
	if !strings.Contains(err.Error(), "trust_mark_issuers") {
		t.Errorf("error = %q, want it to name trust_mark_issuers", err)
	}
}

// A required type with NO configured issuers but the resolved flag ON + a
// configured anchor -> NO boot error (the federation-resolved path IS the
// authorized-issuer source; the anchor provides the root of trust).
func TestBuildFederationConfig_ResolvedFlagSatisfiesIssuerSource_OK(t *testing.T) {
	jwksPath := writeAnchorJWKSFile(t)
	cfg := config.FederationConfig{
		TrustAnchors: []config.TrustAnchorConfig{
			{EntityID: "https://anchor.fed.test", JWKSFile: jwksPath},
		},
		RequiredTrustMarkTypes:                  []string{"https://fed.test/tm/certified"},
		AllowFederationResolvedTrustMarkIssuers: true,
		// No TrustMarkIssuers — the resolved path is the only source, and it's on.
	}
	out, err := buildFederationConfig(cfg)
	if err != nil {
		t.Fatalf("buildFederationConfig(resolved flag + anchor, no configured issuers) = %v, want ok", err)
	}
	if !out.AllowFederationResolvedTrustMarkIssuers {
		t.Error("AllowFederationResolvedTrustMarkIssuers not propagated to the SDK config")
	}
	if len(out.TrustAnchors) != 1 {
		t.Errorf("TrustAnchors length = %d, want 1", len(out.TrustAnchors))
	}
}
