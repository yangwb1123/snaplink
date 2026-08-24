package main

import (
	"context"
	"slices"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// TestWireSigningIssuer_IDTokenAlgs proves the config-facing per-client
// id_token signing keys: with keys.id_token_algs wired, the binary's
// signing-issuer wiring registers the additional issuer BOTH as a token
// issuer (so its public key lands in the aggregated JWKS and hint
// validation can verify tokens it signs) AND via WithIDTokenIssuerAlg (so a
// client declaring id_token_signed_response_alg resolves to it), while
// discovery advertises the union. This is the sso-server binary's half of
// the FAPI 2.0 conformance unblock (design docs/design/per-client-id-token-alg.md).
func TestWireSigningIssuer_IDTokenAlgs(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Issuer: "https://sso.example"},
		Keys: config.KeysConfig{
			Signing: config.SigningConfig{Alg: "es256"},
			IDTokenAlgs: []config.IDTokenAlgConfig{
				{Alg: "rs256"},
			},
		},
	}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireSigningIssuer(); err != nil {
		t.Fatalf("wireSigningIssuer: %v", err)
	}
	if b.signingAlg != "ES256" {
		t.Fatalf("primary signing alg = %q, want ES256", b.signingAlg)
	}
	srv := sso.NewServer(b.opts...)

	ctx := context.Background()
	algs := srv.IDTokenSigningAlgValues(ctx)
	if !slices.Contains(algs, "ES256") || !slices.Contains(algs, "RS256") {
		t.Fatalf("IDTokenSigningAlgValues = %v, want union containing ES256 + RS256", algs)
	}

	// A client declaring RS256 resolves to a dedicated per-alg issuer
	// (id_token emission enabled), while a plain client keeps the
	// default ES256 issuer — byte-identical default path.
	perAlg, emit, err := srv.IDTokenIssuerForClient(&sso.Client{ID: "fapi-login", IDTokenSignedResponseAlg: "RS256"})
	if err != nil {
		t.Fatalf("IDTokenIssuerForClient(RS256 client): %v", err)
	}
	if !emit {
		t.Fatal("emit=false for the wired RS256 per-alg issuer, want true")
	}
	if perAlg == nil {
		t.Fatal("nil issuer for the RS256 client, want the per-alg issuer")
	}
	def, emitDef, err := srv.IDTokenIssuerForClient(&sso.Client{ID: "plain"})
	if err != nil {
		t.Fatalf("IDTokenIssuerForClient(plain client): %v", err)
	}
	if !emitDef {
		t.Fatal("emit=false for the default issuer, want true")
	}
	if def == perAlg {
		t.Fatal("default client resolved to the RS256 per-alg issuer; the default path must keep the primary issuer")
	}
}

// TestWireSigningIssuer_IDTokenAlgsEmpty keeps the default path byte-
// identical: no id_token_algs entries -> no extra options are wired and the
// wired alg set stays the primary's.
func TestWireSigningIssuer_IDTokenAlgsEmpty(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{Issuer: "https://sso.example"},
		Keys:   config.KeysConfig{Signing: config.SigningConfig{Alg: "es256"}},
	}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireSigningIssuer(); err != nil {
		t.Fatalf("wireSigningIssuer: %v", err)
	}
	srv := sso.NewServer(b.opts...)
	algs := srv.IDTokenSigningAlgValues(context.Background())
	if len(algs) != 1 || algs[0] != "ES256" {
		t.Fatalf("IDTokenSigningAlgValues = %v, want exactly [ES256] with no id_token_algs", algs)
	}
}
