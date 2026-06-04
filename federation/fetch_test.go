package federation_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/federation"
)

// These tests cover the OpenID Federation 1.0 §8 Federation Fetch endpoint:
// this server acting as a federation SUPERIOR that issues SIGNED Subordinate
// Statements about its configured subordinates. They reuse the shared
// verifyWithSecurity / splitDots / asymmetricAlgs helpers from handler_test.go
// (same federation_test package).

const (
	fedFetchSuperiorID = "https://superior.federation.test"
	fedFetchSubID      = "https://sub.federation.test"
)

// fetchDeps is a hand-built federation.FetchDeps: the SUPERIOR's own Ed25519
// issuer (signs statements + is the JWKS root the statement verifies against),
// a fixed clock (so exp is deterministic), and the operator config carrying the
// subordinate(s).
type fetchDeps struct {
	iss      *defaultimpl.Ed25519JWTIssuer
	cfg      *federation.Config
	cache    *federation.SubordinateStatementCache
	now      time.Time
	issuer   string
	logCalls int
}

func (d *fetchDeps) ResolveIssuer(core.HandlerContext) string                    { return d.issuer }
func (d *fetchDeps) FederationSigner() federation.JWTSigner                      { return d.iss }
func (d *fetchDeps) FederationConfig() *federation.Config                        { return d.cfg }
func (d *fetchDeps) FederationFetchCache() *federation.SubordinateStatementCache { return d.cache }
func (d *fetchDeps) FederationNow() time.Time                                    { return d.now }
func (d *fetchDeps) LogError(string, ...any)                                     { d.logCalls++ }

// subEntity is the test subordinate: its OWN keypair (the keys the superior
// vouches for). A distinct issuer so its published keys differ from the
// superior's — proving the statement's jwks is the SUBORDINATE's keys, not the
// superior's.
func subEntity(t *testing.T) *defaultimpl.Ed25519JWTIssuer {
	t.Helper()
	return defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedFetchSubID))
}

func subKeys(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer) []core.JWK {
	t.Helper()
	ks, err := iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("subordinate JWKS: %v", err)
	}
	return ks
}

func newFetchDeps(t *testing.T, cfg *federation.Config) *fetchDeps {
	t.Helper()
	return &fetchDeps{
		iss:    defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(fedFetchSuperiorID)),
		cfg:    cfg,
		cache:  federation.NewSubordinateStatementCache(),
		now:    time.Unix(1_900_000_000, 0).UTC(),
		issuer: fedFetchSuperiorID,
	}
}

// serveFetch drives HandleFederationFetch over a recorder with the given raw
// query string (e.g. "sub=...&iss=...") and optional If-None-Match.
func serveFetch(d *fetchDeps, rawQuery, ifNoneMatch string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, core.PathFederationFetch+"?"+rawQuery, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}
	rec := httptest.NewRecorder()
	ctx := core.NewContext(rec, req)
	federation.HandleFederationFetch(d, ctx)
	return rec
}

// superiorKeys returns the SUPERIOR's published JWKS — the keys a resolver (or
// this server's own entity-config consumer) verifies the Subordinate Statement
// against (chained trust: the statement is signed by this server's key).
func superiorKeys(t *testing.T, d *fetchDeps) []core.JWK {
	t.Helper()
	ks, err := d.iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("superior JWKS: %v", err)
	}
	return ks
}

// TestFederationFetch_ConfiguredSubordinate_ServesVerifiableStatement is the
// core proof: GET /fetch?sub=<configured> returns 200 + a valid Subordinate
// Statement signed by THIS server, with iss=this server, sub=the subordinate,
// jwks=the configured subordinate keys, and the imposed metadata_policy/
// constraints present; exp-iat == the configured TTL.
func TestFederationFetch_ConfiguredSubordinate_ServesVerifiableStatement(t *testing.T) {
	sub := subEntity(t)
	subKS := subKeys(t, sub)

	maxPath := 1
	policy := map[string]map[string]map[string]any{
		"openid_relying_party": {
			"token_endpoint_auth_method": {"value": "private_key_jwt"},
		},
	}
	d := newFetchDeps(t, &federation.Config{
		EntityStatementTTL: 8 * time.Hour,
		Subordinates: []federation.SubordinateEntity{{
			EntityID:       fedFetchSubID,
			Keys:           subKS,
			MetadataPolicy: policy,
			Constraints:    &federation.EntityConstraints{MaxPathLength: &maxPath},
		}},
	})

	rec := serveFetch(d, "sub="+url.QueryEscape(fedFetchSubID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != federation.ContentTypeEntityStatement {
		t.Errorf("Content-Type = %q, want %q", ct, federation.ContentTypeEntityStatement)
	}
	if cc := rec.Header().Get("Cache-Control"); len(cc) < 6 || cc[:6] != "public" {
		t.Errorf("Cache-Control = %q, want a public max-age (public metadata, not no-store)", cc)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("missing ETag")
	}

	// THE key proof: the Subordinate Statement verifies against THIS server's
	// JWKS (a resolver validates it against this server's entity-config jwks —
	// chained trust). A bad signature fails here.
	payload, err := verifyWithSecurity(rec.Body.String(), superiorKeys(t, d))
	if err != nil {
		t.Fatalf("VerifyCompactJWS against superior JWKS failed: %v", err)
	}
	var claims federation.EntityStatementClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}

	// header typ == entity-statement+jwt.
	parts := splitDots(rec.Body.String())
	if len(parts) != 3 {
		t.Fatalf("body is not a 3-segment compact JWS: %d segments", len(parts))
	}

	// Subordinate Statement: iss == this server (the superior), sub == the
	// subordinate (NOT self-signed: iss != sub).
	if claims.Iss != fedFetchSuperiorID {
		t.Errorf("iss = %q, want the superior %q", claims.Iss, fedFetchSuperiorID)
	}
	if claims.Sub != fedFetchSubID {
		t.Errorf("sub = %q, want the subordinate %q", claims.Sub, fedFetchSubID)
	}
	if claims.Iss == claims.Sub {
		t.Error("iss == sub: a Subordinate Statement must NOT be self-signed")
	}

	// jwks == the subordinate's configured keys (NOT the superior's). Compare
	// the (single) kid.
	if len(claims.JWKS.Keys) != len(subKS) || len(subKS) == 0 {
		t.Fatalf("jwks has %d keys, want the %d configured subordinate keys", len(claims.JWKS.Keys), len(subKS))
	}
	if claims.JWKS.Keys[0].Kid != subKS[0].Kid {
		t.Errorf("jwks kid = %q, want the subordinate's %q", claims.JWKS.Keys[0].Kid, subKS[0].Kid)
	}
	// And NOT the superior's kid (the statement vouches for the subordinate's
	// keys, not its own signing key).
	if claims.JWKS.Keys[0].Kid == superiorKeys(t, d)[0].Kid {
		t.Error("jwks carries the SUPERIOR's key — must carry the SUBORDINATE's vouched keys")
	}

	// The imposed metadata_policy + constraints appear (the OP-side authoring).
	if claims.MetadataPolicy == nil || claims.MetadataPolicy["openid_relying_party"]["token_endpoint_auth_method"]["value"] != "private_key_jwt" {
		t.Errorf("metadata_policy not authored into the statement: %+v", claims.MetadataPolicy)
	}
	if claims.Constraints == nil || claims.Constraints.MaxPathLength == nil || *claims.Constraints.MaxPathLength != 1 {
		t.Errorf("constraints not authored into the statement: %+v", claims.Constraints)
	}

	// exp - iat == the configured TTL, against the fixed clock.
	if got := claims.Exp - claims.Iat; got != int64((8 * time.Hour).Seconds()) {
		t.Errorf("exp-iat = %d, want %d (the configured TTL)", got, int64((8 * time.Hour).Seconds()))
	}
	if claims.Iat != d.now.Unix() {
		t.Errorf("iat = %d, want the injected clock %d", claims.Iat, d.now.Unix())
	}
}

// TestFederationFetch_UnknownSub_404 proves an unknown/unregistered sub →
// 404 not_found (the §8 federation error JSON) and NO statement is issued
// (this server never vouches for an unconfigured entity).
func TestFederationFetch_UnknownSub_404(t *testing.T) {
	sub := subEntity(t)
	d := newFetchDeps(t, &federation.Config{
		Subordinates: []federation.SubordinateEntity{{EntityID: fedFetchSubID, Keys: subKeys(t, sub)}},
	})

	rec := serveFetch(d, "sub="+url.QueryEscape("https://stranger.federation.test"), "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (unknown sub)", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body not JSON: %v (%s)", err, rec.Body.String())
	}
	if body[core.KeyError] != federation.ErrFederationNotFound {
		t.Errorf("error = %q, want %q", body[core.KeyError], federation.ErrFederationNotFound)
	}
	// NO statement: the body must be the error JSON, never a JWS.
	if ct := rec.Header().Get("Content-Type"); ct == federation.ContentTypeEntityStatement {
		t.Error("a statement was issued for an unknown sub — must be a 404 error instead")
	}
}

// TestFederationFetch_MissingSub_400 proves a missing `sub` → 400
// invalid_request (the required parameter is absent — fail-closed, no
// statement).
func TestFederationFetch_MissingSub_400(t *testing.T) {
	sub := subEntity(t)
	d := newFetchDeps(t, &federation.Config{
		Subordinates: []federation.SubordinateEntity{{EntityID: fedFetchSubID, Keys: subKeys(t, sub)}},
	})

	rec := serveFetch(d, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing sub)", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body not JSON: %v", err)
	}
	if body[core.KeyError] != federation.ErrFederationInvalidRequest {
		t.Errorf("error = %q, want %q", body[core.KeyError], federation.ErrFederationInvalidRequest)
	}
}

// TestFederationFetch_IssMismatch_400 proves a supplied `iss` that does NOT
// equal this server's entity id → 400 invalid_request (a superior issues only
// its OWN statements). A MATCHING iss is accepted.
func TestFederationFetch_IssMismatch_400(t *testing.T) {
	sub := subEntity(t)
	d := newFetchDeps(t, &federation.Config{
		Subordinates: []federation.SubordinateEntity{{EntityID: fedFetchSubID, Keys: subKeys(t, sub)}},
	})

	// Wrong iss → 400.
	rec := serveFetch(d, "sub="+url.QueryEscape(fedFetchSubID)+"&iss="+url.QueryEscape("https://other.federation.test"), "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched iss: status = %d, want 400", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[core.KeyError] != federation.ErrFederationInvalidRequest {
		t.Errorf("error = %q, want %q", body[core.KeyError], federation.ErrFederationInvalidRequest)
	}

	// Correct iss → 200 (the optional iss, when present + matching, is fine).
	ok := serveFetch(d, "sub="+url.QueryEscape(fedFetchSubID)+"&iss="+url.QueryEscape(fedFetchSuperiorID), "")
	if ok.Code != http.StatusOK {
		t.Fatalf("matching iss: status = %d, want 200; body=%s", ok.Code, ok.Body.String())
	}
}

// TestFederationFetch_ETagAnd304 proves the per-(issuer, sub) cache serves a
// matching If-None-Match as 304 (no body) — public metadata caching, mirroring
// the entity-config path.
func TestFederationFetch_ETagAnd304(t *testing.T) {
	sub := subEntity(t)
	d := newFetchDeps(t, &federation.Config{
		Subordinates: []federation.SubordinateEntity{{EntityID: fedFetchSubID, Keys: subKeys(t, sub)}},
	})

	first := serveFetch(d, "sub="+url.QueryEscape(fedFetchSubID), "")
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on first response")
	}
	second := serveFetch(d, "sub="+url.QueryEscape(fedFetchSubID), etag)
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional status = %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("304 carried %d body bytes, want empty", second.Body.Len())
	}
}
