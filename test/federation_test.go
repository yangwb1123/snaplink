package ssotest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (federation route must not be mounted when unwired)", resp.StatusCode)
	}
}

const fedSubID = "https://leaf.subordinate.test"

// fedFetchEntityConfigMeta GETs the server's entity config, verifies it against
// the published JWKS, and returns the federation_entity metadata entry (nil if
// absent). Used to assert federation_fetch_endpoint advertisement gating.
func fedFetchEntityConfigMeta(t *testing.T, base string) *federation.FederationEntityMeta {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/openid-federation")
	if err != nil {
		t.Fatalf("get entity config: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("entity config status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	payload, err := security.VerifyCompactJWS(string(body), fedFetchJWKS(t, base), fedAsymmetricAlgs)
	if err != nil {
		t.Fatalf("verify entity config: %v", err)
	}
	var claims federation.EntityStatementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal entity config claims: %v", err)
	}
	if claims.Metadata == nil {
		return nil
	}
	return claims.Metadata.FederationEntity
}

// TestFederation_Superior_FetchEndpoint is the full-server §8 proof: a real
// *sso.Server configured with a subordinate (a) MOUNTS /fetch which issues a
// signed Subordinate Statement (iss=this server, sub=the subordinate,
// jwks=the configured subordinate keys) that round-trips through the server's
// OWN published JWKS, and (b) ADVERTISES federation_fetch_endpoint in its
// Entity Configuration.
func TestFederation_Superior_FetchEndpoint(t *testing.T) {
	t.Parallel()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "fed-sup", Secret: "s", Active: true, TokenStrategy: "jwt"})

	// The superior's signing issuer (signs both tokens AND the statement).
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedFullIssuer))
	// The subordinate's OWN keypair — the keys the superior vouches for.
	subIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedSubID))
	subKeys, err := subIssuer.JWKS(context.Background())
	if err != nil {
		t.Fatalf("subordinate JWKS: %v", err)
	}

	maxPath := 0
	srv := sso.NewServer(
		sso.WithIssuer(fedFullIssuer),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithFederationEntity(&federation.Config{
			OrganizationName: "Superior Org",
			Subordinates: []federation.SubordinateEntity{{
				EntityID:    fedSubID,
				Keys:        subKeys,
				Constraints: &federation.EntityConstraints{MaxPathLength: &maxPath},
			}},
		}, iss),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// (a) The entity config advertises federation_fetch_endpoint.
	fe := fedFetchEntityConfigMeta(t, httpSrv.URL)
	if fe == nil || fe.FederationFetchEndpoint == "" {
		t.Fatalf("entity config must advertise federation_fetch_endpoint when subordinates configured, got %+v", fe)
	}
	if fe.FederationFetchEndpoint != httpSrv.URL+"/fetch" {
		t.Errorf("federation_fetch_endpoint = %q, want %q", fe.FederationFetchEndpoint, httpSrv.URL+"/fetch")
	}

	// (b) /fetch issues a valid Subordinate Statement about the subordinate.
	resp, err := http.Get(httpSrv.URL + "/fetch?sub=" + url.QueryEscape(fedSubID))
	if err != nil {
		t.Fatalf("get /fetch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/fetch status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/entity-statement+jwt" {
		t.Errorf("Content-Type = %q, want application/entity-statement+jwt", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=") {
		t.Errorf("Cache-Control = %q, want public max-age", cc)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The Subordinate Statement verifies against the SERVER's own JWKS (chained
	// trust — a resolver validates it against the server's entity-config jwks).
	payload, err := security.VerifyCompactJWS(string(body), fedFetchJWKS(t, httpSrv.URL), fedAsymmetricAlgs)
	if err != nil {
		t.Fatalf("verify Subordinate Statement against server JWKS: %v", err)
	}
	var claims federation.EntityStatementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if claims.Iss != fedFullIssuer {
		t.Errorf("iss = %q, want the superior %q", claims.Iss, fedFullIssuer)
	}
	if claims.Sub != fedSubID {
		t.Errorf("sub = %q, want the subordinate %q", claims.Sub, fedSubID)
	}
	if len(claims.JWKS.Keys) == 0 || claims.JWKS.Keys[0].Kid != subKeys[0].Kid {
		t.Errorf("jwks must carry the subordinate's vouched keys, got %+v", claims.JWKS.Keys)
	}
	if claims.Constraints == nil || claims.Constraints.MaxPathLength == nil || *claims.Constraints.MaxPathLength != 0 {
		t.Errorf("imposed constraints not authored into the statement: %+v", claims.Constraints)
	}

	// An unknown sub → 404 not_found (the federation error JSON).
	bad, err := http.Get(httpSrv.URL + "/fetch?sub=" + url.QueryEscape("https://stranger.test"))
	if err != nil {
		t.Fatalf("get /fetch unknown: %v", err)
	}
	defer func() { _ = bad.Body.Close() }()
	if bad.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown sub status = %d, want 404", bad.StatusCode)
	}
	var errBody map[string]string
	if derr := json.NewDecoder(bad.Body).Decode(&errBody); derr != nil {
		t.Fatalf("error body not JSON: %v", derr)
	}
	if errBody["error"] != "not_found" {
		t.Errorf("error = %q, want not_found", errBody["error"])
	}
}

// TestFederation_NoSubordinates_FetchNotMountedAndNotAdvertised proves the
// §8 default-off byte-identical contract: WithFederationEntity but NO
// subordinates ⇒ the entity config is the slice-1 leaf OP (NO
// federation_fetch_endpoint) AND /fetch is NOT mounted (404).
func TestFederation_NoSubordinates_FetchNotMountedAndNotAdvertised(t *testing.T) {
	t.Parallel()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "fed-leaf", Secret: "s", Active: true, TokenStrategy: "jwt"})
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedFullIssuer))
	srv := sso.NewServer(
		sso.WithIssuer(fedFullIssuer),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		// Federation wired, but NO subordinates → leaf OP only.
		sso.WithFederationEntity(&federation.Config{OrganizationName: "Leaf Org"}, iss),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// The entity config must NOT advertise federation_fetch_endpoint.
	fe := fedFetchEntityConfigMeta(t, httpSrv.URL)
	if fe != nil && fe.FederationFetchEndpoint != "" {
		t.Errorf("federation_fetch_endpoint must be absent with no subordinates, got %q", fe.FederationFetchEndpoint)
	}

	// /fetch must NOT be mounted (404).
	resp, err := http.Get(httpSrv.URL + "/fetch?sub=" + url.QueryEscape(fedSubID))
	if err != nil {
		t.Fatalf("get /fetch: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/fetch status = %d, want 404 (route must not be mounted without subordinates)", resp.StatusCode)
	}
}
