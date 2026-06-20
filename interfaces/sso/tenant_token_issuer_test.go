package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// Per-tenant signing-key isolation: a client bound to a tenant with a
// registered tenant issuer (WithTenantTokenIssuer) signs with THAT
// tenant's key, while clients without a tenant mapping fall back to the
// default strategy issuer. All issuers share the one multi-issuer
// validation + aggregated-JWKS machinery, so a tenant-signed token
// validates through the Server unchanged and cross-tenant alg-confusion
// stays structurally impossible (each issuer only trusts its own kid).

// jwtKid extracts the JOSE header `kid` of a compact JWS access token.
func jwtKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWT: %q", token)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("header decode: %v", err)
	}
	var h struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdr, &h); err != nil {
		t.Fatalf("header parse: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Fatalf("unexpected alg %q (want EdDSA)", h.Alg)
	}
	return h.Kid
}

func issueFor(t *testing.T, srv *sso.Server, client *sso.Client) string {
	t.Helper()
	_, ti, err := srv.IssuerForClient(client)
	if err != nil {
		t.Fatalf("IssuerForClient(%s): %v", client.ID, err)
	}
	tok, err := ti.Issue(context.Background(), &sso.Subject{
		ID:       "user-1",
		Provider: "password",
		ClientID: client.ID,
		AMR:      []string{"password"},
	}, []string{"openid"})
	if err != nil {
		t.Fatalf("Issue for %s: %v", client.ID, err)
	}
	if tok.AccessToken == "" {
		t.Fatalf("empty access token for %s", client.ID)
	}
	return tok.AccessToken
}

func TestServer_PerTenantSigningKeyIsolation(t *testing.T) {
	ctx := context.Background()

	// Three independent Ed25519 issuers => three distinct signing keys
	// (distinct kids). "default" is the fallback strategy; tenantA and
	// tenantB are isolated per-tenant issuers.
	def := defaultimpl.NewEd25519JWTIssuer()
	tenantA := defaultimpl.NewEd25519JWTIssuer()
	tenantB := defaultimpl.NewEd25519JWTIssuer()

	// Distinct keys are the whole premise of isolation; guard it.
	if def.KeyID() == tenantA.KeyID() || tenantA.KeyID() == tenantB.KeyID() || def.KeyID() == tenantB.KeyID() {
		t.Fatalf("expected three distinct kids, got def=%s a=%s b=%s",
			def.KeyID(), tenantA.KeyID(), tenantB.KeyID())
	}

	srv := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithTokenIssuer("tenant-a", tenantA),
		sso.WithTokenIssuer("tenant-b", tenantB),
		sso.WithDefaultTokenStrategy("default"),
		sso.WithTenantTokenIssuer("ta", "tenant-a"),
		sso.WithTenantTokenIssuer("tb", "tenant-b"),
	)

	clientA := &sso.Client{ID: "ca", TenantID: "ta"}
	clientB := &sso.Client{ID: "cb", TenantID: "tb"}
	clientNoTenant := &sso.Client{ID: "cn"}
	// A tenant with NO mapping must fall back to the default strategy
	// (empty mapping is not the same as "isolated").
	clientUnmappedTenant := &sso.Client{ID: "cu", TenantID: "tc"}

	// 1) Tenant client signs with its tenant's key (kid binding).
	tokA := issueFor(t, srv, clientA)
	if got := jwtKid(t, tokA); got != tenantA.KeyID() {
		t.Fatalf("tenant A token signed by kid %q, want tenant-a kid %q", got, tenantA.KeyID())
	}
	tokB := issueFor(t, srv, clientB)
	if got := jwtKid(t, tokB); got != tenantB.KeyID() {
		t.Fatalf("tenant B token signed by kid %q, want tenant-b kid %q", got, tenantB.KeyID())
	}

	// 2) Fallback: no tenant, and tenant without a mapping, both use default.
	tokN := issueFor(t, srv, clientNoTenant)
	if got := jwtKid(t, tokN); got != def.KeyID() {
		t.Fatalf("no-tenant token signed by kid %q, want default kid %q", got, def.KeyID())
	}
	tokU := issueFor(t, srv, clientUnmappedTenant)
	if got := jwtKid(t, tokU); got != def.KeyID() {
		t.Fatalf("unmapped-tenant token signed by kid %q, want default kid %q", got, def.KeyID())
	}

	// 3) Every issued token validates through the Server's single
	// multi-issuer validation path (validateAnyToken aggregates issuers).
	for name, tok := range map[string]string{"A": tokA, "B": tokB, "none": tokN, "unmapped": tokU} {
		claims, err := srv.ValidateToken(ctx, tok)
		if err != nil {
			t.Fatalf("ValidateToken(%s): %v", name, err)
		}
		if claims.Subject != "user-1" {
			t.Fatalf("ValidateToken(%s): subject %q, want user-1", name, claims.Subject)
		}
		// RFC 9068 §2.2: client_id MUST be present.
		if claims.ClientID == "" {
			t.Fatalf("ValidateToken(%s): empty client_id (RFC 9068 §2.2)", name)
		}
	}

	// 4) Cross-tenant crypto isolation: tenant A's token must NOT verify
	// against tenant B's issuer in isolation. The kid in A's header is
	// unknown to B (B never holds A's verify key), so B rejects it before
	// any signature check — this is the structural alg-confusion guard
	// (AGENTS.md §2: strict per-issuer kid->alg). If this ever passed, one
	// tenant could be impersonated under another tenant's key.
	if _, err := tenantB.Validate(ctx, tokA); err == nil {
		t.Fatal("tenant B issuer accepted tenant A's token (crypto isolation broken)")
	}
	if _, err := tenantA.Validate(ctx, tokB); err == nil {
		t.Fatal("tenant A issuer accepted tenant B's token (crypto isolation broken)")
	}
	// And the default issuer (the fallback) must not accept a tenant token.
	if _, err := def.Validate(ctx, tokA); err == nil {
		t.Fatal("default issuer accepted tenant A's token (crypto isolation broken)")
	}
}

// A per-tenant mapping must win over a client's own TokenStrategy, so a
// client cannot opt itself out of its tenant's signing key.
func TestServer_TenantIssuerBeatsClientStrategy(t *testing.T) {
	shared := defaultimpl.NewEd25519JWTIssuer()
	isolated := defaultimpl.NewEd25519JWTIssuer()

	srv := sso.NewServer(
		sso.WithTokenIssuer("shared", shared),
		sso.WithTokenIssuer("isolated", isolated),
		sso.WithDefaultTokenStrategy("shared"),
		sso.WithTenantTokenIssuer("ta", "isolated"),
	)

	// Client explicitly asks for "shared", but its tenant pins "isolated".
	c := &sso.Client{ID: "ca", TenantID: "ta", TokenStrategy: "shared"}
	name, ti, err := srv.IssuerForClient(c)
	if err != nil {
		t.Fatalf("IssuerForClient: %v", err)
	}
	if name != "isolated" {
		t.Fatalf("strategy %q, want isolated (tenant mapping must win over client TokenStrategy)", name)
	}
	tok, err := ti.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: c.ID}, []string{"openid"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if got := jwtKid(t, tok.AccessToken); got != isolated.KeyID() {
		t.Fatalf("signed by kid %q, want isolated kid %q", got, isolated.KeyID())
	}
}

// A tenant mapping that names an unregistered issuer must fail closed:
// returning an error rather than silently falling back to the default key
// (which would defeat isolation by leaking the tenant onto a shared key).
func TestServer_TenantIssuerUnregisteredFailsClosed(t *testing.T) {
	def := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithDefaultTokenStrategy("default"),
		// "missing" is never registered via WithTokenIssuer.
		sso.WithTenantTokenIssuer("ta", "missing"),
	)

	c := &sso.Client{ID: "ca", TenantID: "ta"}
	name, ti, err := srv.IssuerForClient(c)
	if err == nil {
		t.Fatalf("expected error for unregistered tenant issuer, got strategy %q issuer %v", name, ti)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("error %q should name the unregistered strategy", err.Error())
	}
}
