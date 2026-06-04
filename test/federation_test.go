package ssotest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/federation"
	"github.com/snaplink/sso/security"
)

// This is the FULL-SERVER companion to federation/handler_test.go: that suite
// drives HandleEntityConfiguration over a hand-built Deps; this one proves the
// END-TO-END wiring — that a real *sso.Server (route mounted by Mount via
// WithFederationEntity) serves a signed Entity Statement that round-trips
// through security.VerifyCompactJWS against the server's OWN published JWKS
// (the same keys an external federation consumer fetches), AND that without the
// option the route is NOT mounted (404, byte-identical-off proof).

const fedFullIssuer = "https://fullserver.federation.test"

// fedAsymmetricAlgs is the asymmetric-alg allowlist for verifying the Entity
// Statement signature — the OP signs with EdDSA here; symmetric algs are
// refused by VerifyCompactJWS regardless.
var fedAsymmetricAlgs = map[string]struct{}{
	"EdDSA": {}, "ES256": {}, "RS256": {}, "PS256": {},
}

// fedFetchJWKS GETs the server's /.well-known/jwks.json and returns its keys —
// the published key set a federation consumer would itself fetch.
func fedFetchJWKS(t *testing.T, base string) []core.JWK {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("get jwks: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d", resp.StatusCode)
	}
	var doc struct {
		Keys []core.JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) == 0 {
		t.Fatal("server JWKS is empty")
	}
	return doc.Keys
}

func TestFederation_FullServer_ServesVerifiableEntityConfig(t *testing.T) {
	t.Parallel()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "fed-c", Secret: "s", Active: true, TokenStrategy: "jwt"})

	// One Ed25519 issuer mints tokens, populates JWKS, AND signs the entity
	// statement — so the statement verifies against the published key set.
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedFullIssuer))

	srv := sso.NewServer(
		sso.WithIssuer(fedFullIssuer),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithFederationEntity(&federation.Config{
			AuthorityHints:     []string{"https://federation.test/anchor"},
			OrganizationName:   "Full Server Org",
			Contacts:           []string{"mailto:ops@fullserver.federation.test"},
			EntityStatementTTL: 6 * time.Hour,
		}, iss),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("get entity config: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/entity-statement+jwt" {
		t.Errorf("Content-Type = %q, want application/entity-statement+jwt", ct)
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("Cache-Control = %q, want a public max-age (public metadata, not no-store)", cc)
	}
	if etag := resp.Header.Get("ETag"); !strings.HasPrefix(etag, `"`) {
		t.Errorf("ETag = %q, want a quoted strong validator", etag)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	// THE key proof: the entity statement verifies against the server's OWN
	// published JWKS (fetched over HTTP, exactly as a federation consumer
	// would). A bad signature fails the test.
	jwks := fedFetchJWKS(t, httpSrv.URL)
	payload, err := security.VerifyCompactJWS(string(body), jwks, fedAsymmetricAlgs)
	if err != nil {
		t.Fatalf("VerifyCompactJWS against server JWKS failed: %v", err)
	}

	var claims federation.EntityStatementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	// Self-signed: iss == sub == issuer.
	if claims.Iss != fedFullIssuer || claims.Sub != fedFullIssuer {
		t.Errorf("iss/sub = %q/%q, want both %q", claims.Iss, claims.Sub, fedFullIssuer)
	}
	if claims.Metadata == nil || claims.Metadata.OP == nil {
		t.Fatal("metadata.openid_provider missing")
	}
	// openid_provider metadata is derived from the discovery doc — its issuer
	// + endpoints must reflect the live server.
	op := claims.Metadata.OP
	if op.Issuer != fedFullIssuer {
		t.Errorf("openid_provider.issuer = %q, want %q", op.Issuer, fedFullIssuer)
	}
	if op.AuthorizationEndpoint == "" || op.TokenEndpoint == "" || op.JWKSURI == "" {
		t.Errorf("derived OP metadata missing endpoints: %+v", op)
	}
	if len(claims.JWKS.Keys) == 0 {
		t.Error("jwks.keys empty — must carry the OP signing keys")
	}
	if len(claims.AuthorityHints) != 1 {
		t.Errorf("authority_hints = %v, want one configured hint", claims.AuthorityHints)
	}
	if fe := claims.Metadata.FederationEntity; fe == nil || fe.OrganizationName != "Full Server Org" {
		t.Errorf("federation_entity not threaded through: %+v", fe)
	}

	// Verify the header typ over the raw compact form.
	if seg := strings.SplitN(string(body), ".", 2); len(seg) == 2 {
		hb, derr := base64.RawURLEncoding.DecodeString(seg[0])
		if derr != nil {
			t.Fatalf("decode header: %v", derr)
		}
		var hdr struct {
			Typ string `json:"typ"`
		}
		if jerr := json.Unmarshal(hb, &hdr); jerr != nil {
			t.Fatalf("parse header: %v", jerr)
		}
		if hdr.Typ != "entity-statement+jwt" {
			t.Errorf("header typ = %q, want entity-statement+jwt", hdr.Typ)
		}
	} else {
		t.Fatalf("body is not a compact JWS: %q", string(body))
	}
}

// TestFederation_DefaultOff_NotMounted proves the default-off byte-identical
// contract: WITHOUT WithFederationEntity the route is NOT mounted (404).
func TestFederation_DefaultOff_NotMounted(t *testing.T) {
	t.Parallel()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "fed-off", Secret: "s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Get(httpSrv.URL + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (federation route must not be mounted when unwired)", resp.StatusCode)
	}
}
