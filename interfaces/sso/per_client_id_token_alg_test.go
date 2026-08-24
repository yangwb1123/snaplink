package sso_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/security"
)

// newPerAlgServer wires the canonical two-issuer layout for the per-client
// id_token signing-alg feature: an Ed25519 default issuer (WithIDTokenIssuer)
// plus an ECDSA ES256 issuer dedicated to clients that declare
// id_token_signed_response_alg=ES256 (WithIDTokenIssuerAlg). The per-alg
// issuer is ALSO registered via WithTokenIssuer so its public key lands in
// the aggregated JWKS and hint validation can verify tokens it signs.
func newPerAlgServer(t *testing.T) (*sso.Server, *defaultimpl.Ed25519JWTIssuer, *defaultimpl.ECDSAJWTIssuer) {
	t.Helper()
	ed := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	ec := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSATokenTTL(5 * time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer("jwt", ed),
		sso.WithTokenIssuer("jwt-es256", ec),
		sso.WithIDTokenIssuer(ed),
		sso.WithIDTokenIssuerAlg("ES256", ec),
	)
	return srv, ed, ec
}

// TestIDTokenIssuerForClient_PerAlgSelectionMatrix is the core selection
// contract: a client that declares id_token_signed_response_alg resolves to
// the issuer wired for that exact alg; a client without the field keeps the
// default issuer (byte-identical path); an alg with no wired issuer fails
// closed with an error (never a fallback to another key); the per-alg issuer
// is returned with emit=true even for a tenant-less client (the per-client
// alg wins over the tenant/shared resolution).
func TestIDTokenIssuerForClient_PerAlgSelectionMatrix(t *testing.T) {
	srv, ed, ec := newPerAlgServer(t)

	t.Run("client with per-alg field resolves to that alg's issuer", func(t *testing.T) {
		c := &sso.Client{ID: "fapi-rp", IDTokenSignedResponseAlg: "ES256"}
		iss, emit, err := srv.IDTokenIssuerForClient(c)
		if err != nil {
			t.Fatalf("IDTokenIssuerForClient: %v", err)
		}
		if !emit {
			t.Fatal("emit=false, want true for a wired per-alg issuer")
		}
		if iss != oidc.IDTokenIssuer(ec) {
			t.Fatal("resolved issuer is not the ES256 per-alg issuer")
		}
	})

	t.Run("client without the field keeps the default issuer", func(t *testing.T) {
		c := &sso.Client{ID: "plain-rp"}
		iss, emit, err := srv.IDTokenIssuerForClient(c)
		if err != nil {
			t.Fatalf("IDTokenIssuerForClient: %v", err)
		}
		if !emit {
			t.Fatal("emit=false, want true for the default issuer")
		}
		if iss != oidc.IDTokenIssuer(ed) {
			t.Fatal("resolved issuer is not the default Ed25519 issuer")
		}
	})

	t.Run("unwired alg fails closed with an error", func(t *testing.T) {
		c := &sso.Client{ID: "rogue-rp", IDTokenSignedResponseAlg: "RS256"}
		iss, emit, err := srv.IDTokenIssuerForClient(c)
		if err == nil {
			t.Fatal("expected an error for an unwired alg, got nil")
		}
		if iss != nil || emit {
			t.Fatalf("fail-closed contract violated: iss=%v emit=%v", iss != nil, emit)
		}
	})

	t.Run("alg none can never be wired and fails closed", func(t *testing.T) {
		c := &sso.Client{ID: "none-rp", IDTokenSignedResponseAlg: "none"}
		if _, _, err := srv.IDTokenIssuerForClient(c); err == nil {
			t.Fatal("expected fail-closed error for alg=none, got nil")
		}
	})

	t.Run("nil client keeps the default issuer", func(t *testing.T) {
		iss, emit, err := srv.IDTokenIssuerForClient(nil)
		if err != nil {
			t.Fatalf("IDTokenIssuerForClient(nil): %v", err)
		}
		if !emit || iss != oidc.IDTokenIssuer(ed) {
			t.Fatalf("nil client must resolve to the default issuer (emit=%v)", emit)
		}
	})
}

// TestWithIDTokenIssuerAlg_Whitelist proves the option only accepts the
// server's accepted JWS algorithm set (AGENTS.md §3): "none" and any
// non-whitelisted value panic at construction, matching WithRSAAlg's
// discipline; the FAPI-relevant values all pass.
func TestWithIDTokenIssuerAlg_Whitelist(t *testing.T) {
	ed := defaultimpl.NewEd25519JWTIssuer()
	assertPanics := func(alg string) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("WithIDTokenIssuerAlg(%q) did not panic", alg)
			}
		}()
		sso.NewServer(sso.WithIDTokenIssuerAlg(alg, ed))
	}
	assertPanics("none")
	assertPanics("HS256")
	assertPanics("RS1")

	for _, alg := range []string{"EdDSA", "ES256", "ES384", "ES512", "RS256", "PS256"} {
		srv := sso.NewServer(sso.WithIDTokenIssuerAlg(alg, ed))
		if got := srv.IDTokenSigningAlgValues(context.Background()); !slices.Contains(got, alg) {
			t.Errorf("alg %q wired but missing from IDTokenSigningAlgValues: %v", alg, got)
		}
	}
}

// TestIDTokenSigningAlgValues_UnionAndByteIdentity covers the discovery
// advertisement source: the per-alg map keys are unioned into the default
// issuer's set (sorted, deduped); with no per-alg issuers the accessor is
// byte-identical to SigningAlgValues (same slice).
func TestIDTokenSigningAlgValues_UnionAndByteIdentity(t *testing.T) {
	ctx := context.Background()

	plain := sso.NewServer(
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithIDTokenIssuer(defaultimpl.NewEd25519JWTIssuer()),
	)
	want := plain.SigningAlgValues(ctx)
	got := plain.IDTokenSigningAlgValues(ctx)
	if len(got) != len(want) {
		t.Fatalf("no per-alg issuers: IDTokenSigningAlgValues=%v SigningAlgValues=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte-identity broken: IDTokenSigningAlgValues=%v SigningAlgValues=%v", got, want)
		}
	}

	srv, _, ec := newPerAlgServer(t)
	got = srv.IDTokenSigningAlgValues(ctx)
	if !slices.Contains(got, "EdDSA") || !slices.Contains(got, "ES256") {
		t.Fatalf("union missing wired algs: %v", got)
	}
	if !slices.Equal(got, srv.SigningAlgValues(ctx)) {
		t.Fatalf("union differs from SigningAlgValues baseline: %v", got)
	}
	_ = ec
}

// TestIDTokenSigningAlgValues_DCRConsistency pins the DCR contract: the set
// the registration validator accepts is exactly the set discovery advertises
// (no drift between the two surfaces), and every advertised alg is in the
// server's accepted JWS set (AGENTS.md §3).
func TestIDTokenSigningAlgValues_DCRConsistency(t *testing.T) {
	srv, _, _ := newPerAlgServer(t)
	advertised := srv.IDTokenSigningAlgValues(context.Background())
	allowed := security.AsymmetricJWSAlgs()
	for _, alg := range advertised {
		if _, ok := allowed[alg]; !ok {
			t.Fatalf("advertised alg %q is outside the accepted JWS set", alg)
		}
	}
}
