package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/protocols/oidc"
)

// Per-tenant signing-key isolation extended to id_token + JARM.
//
// A client bound to a tenant with a registered tenant issuer
// (WithTenantTokenIssuer) signs ALL of its token types — access token,
// id_token and JARM authorization response — with THAT tenant's key,
// while clients without a tenant mapping fall back to the shared
// idTokenIssuer / jarmSigner. All issuers share the one multi-issuer
// validation + aggregated-JWKS machinery, so a tenant-signed token
// validates through the Server unchanged and cross-tenant alg-confusion
// stays structurally impossible (each issuer only trusts its own kid).
//
// These tests use real Ed25519 / session issuers (no mocks), per the
// repo's no-mock-storage rule.

// joseKid extracts the JOSE header `kid` of a compact JWS (access or
// id token), asserting the alg is EdDSA along the way.
func joseKid(t *testing.T, token string) string {
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

// issueIDTokenFor resolves the per-tenant id_token issuer for client and
// mints an id_token, failing the test on resolution error or an
// unexpected omission.
func issueIDTokenFor(t *testing.T, srv *sso.Server, client *sso.Client) string {
	t.Helper()
	iss, emit, err := srv.IDTokenIssuerForClient(client)
	if err != nil {
		t.Fatalf("IDTokenIssuerForClient(%s): %v", client.ID, err)
	}
	if !emit {
		t.Fatalf("IDTokenIssuerForClient(%s): emit=false, expected an issuer", client.ID)
	}
	tok, err := iss.IssueIDToken(context.Background(), &oidc.IDTokenRequest{
		Subject:  "user-1",
		Audience: client.ID,
	})
	if err != nil {
		t.Fatalf("IssueIDToken(%s): %v", client.ID, err)
	}
	if tok == "" {
		t.Fatalf("empty id_token for %s", client.ID)
	}
	return tok
}

func TestServer_PerTenantIDTokenIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Three independent Ed25519 issuers => three distinct signing keys.
	// Each satisfies TokenIssuer AND oidc.IDTokenIssuer, so one object
	// signs both access tokens and id_tokens for its tenant.
	def := defaultimpl.NewEd25519JWTIssuer()
	tenantA := defaultimpl.NewEd25519JWTIssuer()
	tenantB := defaultimpl.NewEd25519JWTIssuer()

	if def.KeyID() == tenantA.KeyID() || tenantA.KeyID() == tenantB.KeyID() || def.KeyID() == tenantB.KeyID() {
		t.Fatalf("expected three distinct kids, got def=%s a=%s b=%s",
			def.KeyID(), tenantA.KeyID(), tenantB.KeyID())
	}

	srv := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithTokenIssuer("tenant-a", tenantA),
		sso.WithTokenIssuer("tenant-b", tenantB),
		sso.WithDefaultTokenStrategy("default"),
		// The shared idTokenIssuer is the SAME object as the default
		// access-token strategy — the canonical single-key wiring.
		sso.WithIDTokenIssuer(def),
		sso.WithTenantTokenIssuer("ta", "tenant-a"),
		sso.WithTenantTokenIssuer("tb", "tenant-b"),
	)

	clientA := &sso.Client{ID: "ca", TenantID: "ta"}
	clientB := &sso.Client{ID: "cb", TenantID: "tb"}
	clientNoTenant := &sso.Client{ID: "cn"}
	clientUnmappedTenant := &sso.Client{ID: "cu", TenantID: "tc"}

	// 1) Tenant client's id_token is signed by its tenant's key (kid).
	idA := issueIDTokenFor(t, srv, clientA)
	if got := joseKid(t, idA); got != tenantA.KeyID() {
		t.Fatalf("tenant A id_token signed by kid %q, want tenant-a kid %q", got, tenantA.KeyID())
	}
	idB := issueIDTokenFor(t, srv, clientB)
	if got := joseKid(t, idB); got != tenantB.KeyID() {
		t.Fatalf("tenant B id_token signed by kid %q, want tenant-b kid %q", got, tenantB.KeyID())
	}

	// 2) Fallback: no tenant, and a tenant without a mapping, both use
	// the shared idTokenIssuer (== default key).
	idN := issueIDTokenFor(t, srv, clientNoTenant)
	if got := joseKid(t, idN); got != def.KeyID() {
		t.Fatalf("no-tenant id_token signed by kid %q, want default kid %q", got, def.KeyID())
	}
	idU := issueIDTokenFor(t, srv, clientUnmappedTenant)
	if got := joseKid(t, idU); got != def.KeyID() {
		t.Fatalf("unmapped-tenant id_token signed by kid %q, want default kid %q", got, def.KeyID())
	}

	// 3) Every id_token validates through the Server's single
	// multi-issuer validation path (validateAnyToken aggregates issuers,
	// so a tenant-signed id_token verifies with no extra wiring).
	for name, tok := range map[string]string{"A": idA, "B": idB, "none": idN, "unmapped": idU} {
		claims, err := srv.ValidateToken(ctx, tok)
		if err != nil {
			t.Fatalf("ValidateToken(id %s): %v", name, err)
		}
		if claims.Subject != "user-1" {
			t.Fatalf("ValidateToken(id %s): subject %q, want user-1", name, claims.Subject)
		}
	}

	// 4) Cross-tenant crypto isolation: tenant A's id_token must NOT
	// verify against tenant B's issuer in isolation (B never holds A's
	// verify key; the kid is unknown so B rejects before any signature
	// check — the structural alg-confusion guard, AGENTS.md §2).
	if _, err := tenantB.Validate(ctx, idA); err == nil {
		t.Fatal("tenant B issuer accepted tenant A's id_token (crypto isolation broken)")
	}
	if _, err := def.Validate(ctx, idA); err == nil {
		t.Fatal("default issuer accepted tenant A's id_token (crypto isolation broken)")
	}

	// 5) Access token and id_token for the same tenant client share one
	// key — the whole point of routing both through the tenant issuer.
	_, ti, err := srv.IssuerForClient(clientA)
	if err != nil {
		t.Fatalf("IssuerForClient(ca): %v", err)
	}
	at, err := ti.Issue(ctx, &sso.Subject{ID: "user-1", ClientID: clientA.ID}, []string{"openid"})
	if err != nil {
		t.Fatalf("access Issue(ca): %v", err)
	}
	if joseKid(t, at.AccessToken) != joseKid(t, idA) {
		t.Fatalf("tenant A access token kid %q != id_token kid %q (not the same key)",
			joseKid(t, at.AccessToken), joseKid(t, idA))
	}
}

// A tenant mapping that names an unregistered issuer must fail closed for
// id_token: returning an error rather than silently falling back to the
// shared idTokenIssuer (which would leak the tenant onto a shared key).
func TestServer_TenantIDTokenUnregisteredFailsClosed(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer()
	srv := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithDefaultTokenStrategy("default"),
		sso.WithIDTokenIssuer(def),
		// "missing" is never registered via WithTokenIssuer.
		sso.WithTenantTokenIssuer("ta", "missing"),
	)

	c := &sso.Client{ID: "ca", TenantID: "ta"}
	iss, emit, err := srv.IDTokenIssuerForClient(c)
	if err == nil {
		t.Fatalf("expected error for unregistered tenant id_token issuer, got issuer=%v emit=%v", iss, emit)
	}
	if emit {
		t.Fatal("emit must be false when the tenant issuer is unregistered (fail closed)")
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Fatalf("error %q should name the unregistered strategy", err.Error())
	}
}

// A tenant whose registered strategy is opaque/session (a TokenIssuer
// that does NOT implement oidc.IDTokenIssuer) must omit the id_token
// (emit=false, no error) rather than sign it with the shared key —
// fail-closed by omission. The access-token path is unaffected.
func TestServer_TenantIDTokenNonOIDCIssuerOmits(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer()
	session := defaultimpl.NewSessionTokenIssuer() // TokenIssuer, not IDTokenIssuer

	srv := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithTokenIssuer("opaque", session),
		sso.WithDefaultTokenStrategy("default"),
		sso.WithIDTokenIssuer(def),
		sso.WithTenantTokenIssuer("ta", "opaque"),
	)

	c := &sso.Client{ID: "ca", TenantID: "ta"}

	// id_token: omitted (emit=false), and crucially NOT signed by the
	// shared default key.
	iss, emit, err := srv.IDTokenIssuerForClient(c)
	if err != nil {
		t.Fatalf("IDTokenIssuerForClient(opaque tenant): unexpected error %v", err)
	}
	if emit || iss != nil {
		t.Fatalf("opaque tenant id_token must be omitted (emit=false, iss=nil), got emit=%v iss=%v", emit, iss)
	}

	// Access token still works — only id_token is withheld.
	_, ti, err := srv.IssuerForClient(c)
	if err != nil {
		t.Fatalf("IssuerForClient(opaque tenant): %v", err)
	}
	tok, err := ti.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: c.ID}, []string{"openid"})
	if err != nil {
		t.Fatalf("access Issue(opaque tenant): %v", err)
	}
	if tok.AccessToken == "" {
		t.Fatal("opaque tenant access token empty")
	}
}

// JARM per-tenant isolation: a tenant's authorization response JWT is
// signed by the tenant's key; unmapped tenants fall back to the shared
// signer; an opaque/unregistered tenant issuer fails closed (ok=false →
// caller omits + invalid_request, never a bare code under the shared key).
func TestServer_PerTenantJARMIsolation(t *testing.T) {
	t.Parallel()
	def := defaultimpl.NewEd25519JWTIssuer()
	tenantA := defaultimpl.NewEd25519JWTIssuer()
	session := defaultimpl.NewSessionTokenIssuer()

	srv := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithTokenIssuer("tenant-a", tenantA),
		sso.WithTokenIssuer("opaque", session),
		sso.WithDefaultTokenStrategy("default"),
		// JARM reuses the same signing object (Ed25519JWTIssuer satisfies
		// oidc.JARMSigner). Shared signer == default key.
		sso.WithJARM(def),
		sso.WithTenantTokenIssuer("ta", "tenant-a"),
		sso.WithTenantTokenIssuer("topaque", "opaque"),
	)

	ctx := context.Background()

	// Tenant A's JARM response is signed by tenant A's key.
	clientA := &sso.Client{ID: "ca", TenantID: "ta"}
	signerA, ok := srv.JARMSignerForClient(clientA)
	if !ok {
		t.Fatal("expected a JARM signer for tenant A")
	}
	jwtA, err := oidc.SignJARMResponse(ctx, signerA, "https://issuer.example", clientA.ID, "code-a", "state-a")
	if err != nil {
		t.Fatalf("SignJARMResponse(A): %v", err)
	}
	if got := joseKid(t, jwtA); got != tenantA.KeyID() {
		t.Fatalf("tenant A JARM signed by kid %q, want tenant-a kid %q", got, tenantA.KeyID())
	}

	// Unmapped/no-tenant client falls back to the shared signer (default key).
	clientNo := &sso.Client{ID: "cn"}
	signerN, ok := srv.JARMSignerForClient(clientNo)
	if !ok {
		t.Fatal("expected the shared JARM signer for a non-tenant client")
	}
	jwtN, err := oidc.SignJARMResponse(ctx, signerN, "https://issuer.example", clientNo.ID, "code-n", "")
	if err != nil {
		t.Fatalf("SignJARMResponse(none): %v", err)
	}
	if got := joseKid(t, jwtN); got != def.KeyID() {
		t.Fatalf("no-tenant JARM signed by kid %q, want default kid %q", got, def.KeyID())
	}

	// Opaque tenant strategy can't sign JARM → fail closed (ok=false).
	clientOpaque := &sso.Client{ID: "co", TenantID: "topaque"}
	if _, ok := srv.JARMSignerForClient(clientOpaque); ok {
		t.Fatal("opaque tenant must fail JARM closed (ok=false), not return a signer")
	}

	// Unregistered tenant issuer also fails closed.
	srvMissing := sso.NewServer(
		sso.WithTokenIssuer("default", def),
		sso.WithDefaultTokenStrategy("default"),
		sso.WithJARM(def),
		sso.WithTenantTokenIssuer("tx", "missing"),
	)
	if _, ok := srvMissing.JARMSignerForClient(&sso.Client{ID: "cx", TenantID: "tx"}); ok {
		t.Fatal("unregistered tenant issuer must fail JARM closed (ok=false)")
	}
}
