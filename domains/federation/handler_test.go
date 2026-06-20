package federation_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// verifyWithSecurity is the (federation-independent) signature check: the
// shared security.VerifyCompactJWS primitive validates the Entity Statement
// against the OP's JWKS, exactly as an external federation consumer would.
func verifyWithSecurity(compact string, keys []core.JWK) ([]byte, error) {
	return security.VerifyCompactJWS(compact, keys, asymmetricAlgs)
}

// fedTestIssuer is the entity identifier (iss == sub) the test OP publishes
// itself under.
const fedTestIssuer = "https://op.federation.test"

// asymmetricAlgs is the alg allowlist the test passes to the (federation-
// independent) verification of the Entity Statement. EdDSA is what the
// Ed25519 issuer signs with; a symmetric alg is rejected by the verifier
// itself, so this list is purely the asymmetric set the OP key uses.
var asymmetricAlgs = map[string]struct{}{
	"EdDSA": {}, "ES256": {}, "ES384": {}, "ES512": {},
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
}

// fedDeps is a hand-built federation.Deps for the unit test: a real Ed25519
// issuer (signer + JWKS source), a fixed clock, and a static config. It
// computes the SAME fixed `now` the assertions use, so exp is deterministic
// — no real-clock-vs-fixed-time date bomb.
type fedDeps struct {
	iss    *defaultimpl.Ed25519JWTIssuer
	cfg    *federation.Config
	cache  *federation.EntityConfigCache
	now    time.Time
	base   string
	issuer string
}

func (d *fedDeps) ResolveIssuer(core.HandlerContext) string  { return d.issuer }
func (d *fedDeps) RequestBaseURL(core.HandlerContext) string { return d.base }
func (d *fedDeps) TokenIssuers() map[string]core.TokenIssuer {
	return map[string]core.TokenIssuer{"jwt": d.iss}
}
func (d *fedDeps) BuildOPMetadata(_ core.HandlerContext, base string) federation.OPFederationMetadata {
	// A minimal but realistic projection — the production server derives this
	// from the discovery doc; here we hand a representative subset so the test
	// can assert openid_provider.issuer is threaded through unchanged.
	return federation.OPFederationMetadata{
		Issuer:                 d.issuer,
		AuthorizationEndpoint:  base + "/auth/login",
		TokenEndpoint:          base + "/token",
		JWKSURI:                base + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{"code"},
		SubjectTypesSupported:  []string{"public"},
	}
}
func (d *fedDeps) FederationSigner() federation.JWTSigner         { return d.iss }
func (d *fedDeps) FederationConfig() *federation.Config           { return d.cfg }
func (d *fedDeps) FederationCache() *federation.EntityConfigCache { return d.cache }
func (d *fedDeps) FederationNow() time.Time                       { return d.now }
func (d *fedDeps) LogError(string, ...any)                        {}

func newFedDeps(t *testing.T, cfg *federation.Config) *fedDeps {
	t.Helper()
	return &fedDeps{
		iss:    defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedTestIssuer)),
		cfg:    cfg,
		cache:  federation.NewEntityConfigCache(),
		now:    time.Unix(1_900_000_000, 0).UTC(), // fixed clock (well past, never a date bomb)
		base:   fedTestIssuer,
		issuer: fedTestIssuer,
	}
}

// serveEntityConfig drives HandleEntityConfiguration over a recorder and
// returns the response.
func serveEntityConfig(d *fedDeps, ifNoneMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, core.PathFederationEntityConfig, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, req)
	federation.HandleEntityConfiguration(d, ctx)
	return rec
}

// decodedStatement is the verified Entity Statement payload.
type decodedStatement struct {
	hdrTyp string
	claims federation.EntityStatementClaims
}

// verifyEntityStatement asserts the body is a 3-segment compact JWS that
// VerifyCompactJWS validates against the OP's JWKS (THE key proof), then
// returns the decoded header typ + claims.
func verifyEntityStatement(t *testing.T, d *fedDeps, body []byte) decodedStatement {
	t.Helper()
	jwks, err := d.iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	// THE key proof: the entity statement is signed by the JWKS key.
	payload, err := verifyWithSecurity(string(body), jwks)
	if err != nil {
		t.Fatalf("VerifyCompactJWS against server JWKS failed: %v", err)
	}
	var claims federation.EntityStatementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	// Header typ.
	parts := splitDots(string(body))
	if len(parts) != 3 {
		t.Fatalf("body is not a 3-segment compact JWS: got %d segments", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatalf("parse header: %v", err)
	}
	return decodedStatement{hdrTyp: hdr.Typ, claims: claims}
}

func splitDots(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func TestEntityConfiguration_ServesVerifiableStatement(t *testing.T) {
	d := newFedDeps(t, &federation.Config{
		AuthorityHints:     []string{"https://federation.test/anchor"},
		OrganizationName:   "Test Org",
		Contacts:           []string{"mailto:admin@op.federation.test"},
		EntityStatementTTL: 12 * time.Hour,
	})

	rec := serveEntityConfig(d, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != federation.ContentTypeEntityStatement {
		t.Errorf("Content-Type = %q, want %q", ct, federation.ContentTypeEntityStatement)
	}
	if cc := rec.Header().Get("Cache-Control"); cc == "" || cc[:6] != "public" {
		t.Errorf("Cache-Control = %q, want a public max-age (not no-store)", cc)
	}

	dec := verifyEntityStatement(t, d, rec.Body.Bytes())

	if dec.hdrTyp != federation.EntityStatementTyp {
		t.Errorf("header typ = %q, want %q", dec.hdrTyp, federation.EntityStatementTyp)
	}
	// Self-signed: iss == sub == issuer.
	if dec.claims.Iss != fedTestIssuer || dec.claims.Sub != fedTestIssuer {
		t.Errorf("iss/sub = %q/%q, want both %q", dec.claims.Iss, dec.claims.Sub, fedTestIssuer)
	}
	if dec.claims.Metadata == nil || dec.claims.Metadata.OP == nil {
		t.Fatal("metadata.openid_provider missing")
	}
	if dec.claims.Metadata.OP.Issuer != fedTestIssuer {
		t.Errorf("metadata.openid_provider.issuer = %q, want %q", dec.claims.Metadata.OP.Issuer, fedTestIssuer)
	}
	if len(dec.claims.JWKS.Keys) == 0 {
		t.Error("jwks.keys is empty — the statement must carry the OP signing keys")
	}
	if len(dec.claims.AuthorityHints) != 1 || dec.claims.AuthorityHints[0] != "https://federation.test/anchor" {
		t.Errorf("authority_hints = %v, want the configured hint", dec.claims.AuthorityHints)
	}
	// federation_entity metadata from config.
	if fe := dec.claims.Metadata.FederationEntity; fe == nil || fe.OrganizationName != "Test Org" {
		t.Errorf("federation_entity.organization_name not threaded through: %+v", fe)
	}
	// exp - iat == EntityStatementTTL, computed against the SAME fixed clock.
	if got := dec.claims.Exp - dec.claims.Iat; got != int64((12 * time.Hour).Seconds()) {
		t.Errorf("exp - iat = %d, want %d (the configured TTL)", got, int64((12 * time.Hour).Seconds()))
	}
	if dec.claims.Iat != d.now.Unix() {
		t.Errorf("iat = %d, want the injected clock %d", dec.claims.Iat, d.now.Unix())
	}
}

func TestEntityConfiguration_ETagAnd304(t *testing.T) {
	d := newFedDeps(t, &federation.Config{})

	first := serveEntityConfig(d, "")
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on the first response")
	}

	// A repeat with the matching If-None-Match must 304 (served from the
	// per-issuer cache) with no body.
	second := serveEntityConfig(d, etag)
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 carried a body of %d bytes, want empty", second.Body.Len())
	}
	if got := second.Header().Get("ETag"); got != etag {
		t.Errorf("304 ETag = %q, want the same %q", got, etag)
	}
}

// TestEntityConfiguration_NoFederationEntityMeta proves the federation_entity
// entry is OMITTED when the operator configures neither org nor contacts.
func TestEntityConfiguration_NoFederationEntityMeta(t *testing.T) {
	d := newFedDeps(t, &federation.Config{})
	rec := serveEntityConfig(d, "")
	dec := verifyEntityStatement(t, d, rec.Body.Bytes())
	if dec.claims.Metadata.FederationEntity != nil {
		t.Errorf("federation_entity should be omitted when unconfigured, got %+v", dec.claims.Metadata.FederationEntity)
	}
	if len(dec.claims.AuthorityHints) != 0 {
		t.Errorf("authority_hints should be omitted when unconfigured, got %v", dec.claims.AuthorityHints)
	}
}
