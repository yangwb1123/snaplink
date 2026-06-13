package ssotest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/federation"
)

// ===========================================================================
// SLICE 3 END-TO-END — automatic federation client registration through a real
// *sso.Server over HTTP. Proves the VALUE: a remote RP that is a VALIDATED
// federation member (its Entity Statement resolves to the configured test
// anchor) presents an authorization request for its entity-ID client_id — which
// is NOT in the ClientStore — and the OP resolves its trust chain on-the-fly,
// derives a policy-constrained client, issues an auth code, and lets the RP
// exchange it at /token via private_key_jwt with its OWN (chain-vouched) key.
// NO manual registration. Also proves default-off: without
// WithFederationAutoRegistration the identical request is invalid_client.
//
// A compact fake federation is built in-package (the federation/ harness is
// package-private). The clock is fixed; no real network.
// ===========================================================================

// frFixedClock is the single instant the test federation is minted + validated
// against (far in the past so it's never a real date bomb).
var frFixedClock = time.Unix(1_900_000_000, 0).UTC()

const (
	frAnchorID   = "https://anchor.fed-e2e.test"
	frInterID    = "https://intermediate.fed-e2e.test"
	frRPID       = "https://rp.fed-e2e.test" // the leaf RP entity id == its client_id
	frAnchorFch  = "https://anchor.fed-e2e.test/fetch"
	frInterFch   = "https://intermediate.fed-e2e.test/fetch"
	frASIssuer   = "https://op.fed-e2e.test"
	frRPRedirect = "https://rp.fed-e2e.test/callback"
	frRPKid      = "rp-protocol-key-1"
	frUserID     = "u-fed"
	frPassword   = "pw-fed"
)

// frEntity is a federation participant: its id + its entity-statement signing
// issuer (a real Ed25519 issuer; its JWKS is its published key set).
type frEntity struct {
	id  string
	iss *defaultimpl.Ed25519JWTIssuer
}

func newFREntity(t *testing.T, id string) *frEntity {
	t.Helper()
	return &frEntity{id: id, iss: defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer(id))}
}

func (e *frEntity) keys(t *testing.T) []core.JWK {
	t.Helper()
	ks, err := e.iss.JWKS(context.Background())
	if err != nil {
		t.Fatalf("JWKS(%s): %v", e.id, err)
	}
	return ks
}

func (e *frEntity) sign(t *testing.T, claims federation.EntityStatementClaims) string {
	t.Helper()
	c, err := e.iss.SignJWT(context.Background(), federation.EntityStatementTyp, claims)
	if err != nil {
		t.Fatalf("SignJWT(%s): %v", e.id, err)
	}
	return c
}

func (e *frEntity) config(t *testing.T, hints []string, fetchEndpoint string, rp map[string]any) string {
	t.Helper()
	meta := &federation.EntityMetadata{}
	if fetchEndpoint != "" {
		meta.FederationEntity = &federation.FederationEntityMeta{FederationFetchEndpoint: fetchEndpoint}
	}
	if rp != nil {
		meta.RP = rp
	}
	return e.sign(t, federation.EntityStatementClaims{
		Iss: e.id, Sub: e.id,
		Iat:            frFixedClock.Unix(),
		Exp:            frFixedClock.Add(24 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: e.keys(t)},
		Metadata:       meta,
		AuthorityHints: hints,
	})
}

func (e *frEntity) subordinate(t *testing.T, subject *frEntity, policy map[string]map[string]map[string]any) string {
	t.Helper()
	return e.sign(t, federation.EntityStatementClaims{
		Iss: e.id, Sub: subject.id,
		Iat:            frFixedClock.Unix(),
		Exp:            frFixedClock.Add(24 * time.Hour).Unix(),
		JWKS:           federation.EntityJWKS{Keys: subject.keys(t)},
		MetadataPolicy: policy,
	})
}

// frFetcher serves the test federation in-memory.
type frFetcher struct {
	configs map[string]string
	subs    map[string]string
}

func (f *frFetcher) FetchEntityConfiguration(_ context.Context, id string) ([]byte, error) {
	c, ok := f.configs[id]
	if !ok {
		return nil, errors.New("no config for " + id)
	}
	return []byte(c), nil
}

func (f *frFetcher) FetchSubordinateStatement(_ context.Context, endpoint, iss, sub string) ([]byte, error) {
	s, ok := f.subs[endpoint+"|"+iss+"|"+sub]
	if !ok {
		return nil, errors.New("no subordinate for " + endpoint + "|" + iss + "|" + sub)
	}
	return []byte(s), nil
}

// frServer holds the wired test server + the RP's PROTOCOL private key (the key
// it authenticates to /token with — distinct from the entity-statement signing
// keys).
type frServer struct {
	http      *httptest.Server
	rpPrivKey ed25519.PrivateKey
}

// buildFederationServer wires a fake anchor->intermediate->RP federation and a
// real *sso.Server. The RP's openid_relying_party metadata carries its protocol
// public key inline (jwks, with kid) so the derived client can verify the RP's
// private_key_jwt. anchorPolicy is the trust anchor's metadata_policy about the
// intermediate (constrains the RP). autoRegister toggles
// WithFederationAutoRegistration (the default-off proof passes false).
func buildFederationServer(t *testing.T, anchorPolicy map[string]map[string]map[string]any, autoRegister bool) *frServer {
	t.Helper()

	anchor := newFREntity(t, frAnchorID)
	inter := newFREntity(t, frInterID)
	rp := newFREntity(t, frRPID)

	// The RP's PROTOCOL keypair (for private_key_jwt at /token) — separate from
	// the entity-statement signing key. Its public JWK (with kid) goes into the
	// RP's openid_relying_party.jwks; the private key signs the token assertion.
	rpPub, rpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("rp protocol keygen: %v", err)
	}
	rpJWKS := map[string]any{"keys": []any{map[string]any{
		"kty": "OKP", "crv": "Ed25519",
		"kid": frRPKid, "alg": "EdDSA", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(rpPub),
	}}}

	rpMeta := map[string]any{
		"client_name":   "Federated E2E RP",
		"redirect_uris": []any{frRPRedirect},
		"scope":         "openid",
		"jwks":          rpJWKS,
	}

	f := &frFetcher{configs: map[string]string{}, subs: map[string]string{}}
	f.configs[anchor.id] = anchor.config(t, nil, frAnchorFch, nil)
	f.configs[inter.id] = inter.config(t, []string{anchor.id}, frInterFch, nil)
	f.configs[rp.id] = rp.config(t, []string{inter.id}, "", rpMeta)
	f.subs[frAnchorFch+"|"+anchor.id+"|"+inter.id] = anchor.subordinate(t, inter, anchorPolicy)
	f.subs[frInterFch+"|"+inter.id+"|"+rp.id] = inter.subordinate(t, rp, nil)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: frUserID})
	clients := defaultimpl.NewMemoryClientStore() // EMPTY — the RP is NOT pre-registered.

	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != frPassword {
				return nil, errors.New("bad password")
			}
			return &sso.AuthResult{UserID: frUserID}, nil
		},
	))

	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer(frASIssuer),
		defaultimpl.WithEd25519TokenTTL(time.Minute),
	)

	fedCfg := &federation.Config{
		// LIVE trust anchor — its configured Keys are the root of trust.
		TrustAnchors: []federation.TrustAnchor{{EntityID: anchor.id, Keys: anchor.keys(t)}},
	}

	opts := []sso.Option{
		sso.WithIssuer(frASIssuer),
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", iss),
		sso.WithIDTokenIssuer(iss),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
		sso.WithFederationEntity(fedCfg, iss,
			federation.WithTrustChainFetcher(f),
			federation.WithTrustChainClock(func() time.Time { return frFixedClock }),
		),
	}
	if autoRegister {
		opts = append(opts, sso.WithFederationAutoRegistration())
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return &frServer{http: httpSrv, rpPrivKey: rpPriv}
}

// loginForCode drives /auth/login response_type=code for the federation RP's
// entity-id client_id. Returns status + body.
func (s *frServer) loginForCode(t *testing.T) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"credential":    map[string]string{"username": "user", "password": frPassword},
		"client_id":     frRPID,
		"response_type": "code",
		"redirect_uri":  frRPRedirect,
		"scope":         []string{"openid"},
		"state":         "xyz",
	})
	resp, err := http.Post(s.http.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// signRPAssertion builds a private_key_jwt assertion signed by the RP's
// protocol key (the key published in its federation RP metadata jwks).
func (s *frServer) signRPAssertion(t *testing.T) string {
	t.Helper()
	now := time.Now().Unix()
	header, _ := json.Marshal(map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": frRPKid})
	claims, _ := json.Marshal(map[string]any{
		"iss": frRPID,
		"sub": frRPID,
		"aud": frASIssuer,
		"exp": now + 60,
		"iat": now,
		"jti": "fed-e2e-jti-1",
	})
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sig := ed25519.Sign(s.rpPrivKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// exchangeCode posts the auth code to /token with the RP's private_key_jwt.
func (s *frServer) exchangeCode(t *testing.T, code string) (int, map[string]any) {
	t.Helper()
	form := "grant_type=authorization_code" +
		"&code=" + code +
		"&redirect_uri=" + frRPRedirect +
		"&client_id=" + frRPID +
		"&client_assertion_type=" + sso.ClientAssertionTypeJWTBearer +
		"&client_assertion=" + s.signRPAssertion(t)
	resp, err := http.Post(s.http.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestFederationAutoRegistration_EndToEnd is the headline proof: a validated
// federation RP logs in (entity-id client_id, not pre-registered), gets a code,
// and exchanges it via private_key_jwt with its chain-vouched key — no manual
// registration anywhere.
func TestFederationAutoRegistration_EndToEnd(t *testing.T) {
	t.Parallel()
	s := buildFederationServer(t, nil, true)

	status, body := s.loginForCode(t)
	if status != http.StatusOK {
		t.Fatalf("login status = %d, body=%v; the federation RP must be admitted", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("no auth code in login response: %v", body)
	}

	tStatus, tBody := s.exchangeCode(t, code)
	if tStatus != http.StatusOK {
		t.Fatalf("token status = %d, body=%v; the RP must exchange the code via private_key_jwt", tStatus, tBody)
	}
	if at, _ := tBody["access_token"].(string); at == "" {
		t.Fatalf("no access_token in token response: %v", tBody)
	}
}

// TestFederationAutoRegistration_DefaultOff proves the byte-identical-off
// contract: the IDENTICAL request, with federation auto-registration NOT wired,
// fails invalid_client (the RP's entity-id client_id is simply unknown).
func TestFederationAutoRegistration_DefaultOff(t *testing.T) {
	t.Parallel()
	s := buildFederationServer(t, nil, false)

	status, body := s.loginForCode(t)
	if status != http.StatusUnauthorized {
		t.Fatalf("login status = %d (body=%v), want 401 — without auto-registration the federation RP is unknown", status, body)
	}
	if body["error"] != "invalid_client" {
		t.Errorf("error = %v, want invalid_client (the same as any unknown client_id)", body["error"])
	}
}

// TestFederationAutoRegistration_PolicyBoundsRedirectURI proves the
// metadata_policy constrains the derived client end-to-end: the trust anchor
// pins redirect_uris to a value that EXCLUDES the redirect the RP request uses,
// so the authz redirect_uri exact-match fails (the derived client never carries
// the requested redirect).
func TestFederationAutoRegistration_PolicyBoundsRedirectURI(t *testing.T) {
	t.Parallel()
	// Policy pins redirect_uris to a DIFFERENT value than frRPRedirect.
	policy := map[string]map[string]map[string]any{
		"openid_relying_party": {
			"redirect_uris": {"value": []any{"https://only-this.fed-e2e.test/cb"}},
		},
	}
	s := buildFederationServer(t, policy, true)

	status, body := s.loginForCode(t)
	// The chain resolves + the client is derived, but its redirect_uris is the
	// policy-pinned value; the request's frRPRedirect is not in it → invalid
	// redirect_uri (400).
	if status != http.StatusBadRequest {
		t.Fatalf("login status = %d (body=%v), want 400 — the policy-pinned redirect_uris must exclude the requested one", status, body)
	}
	if body["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %v, want invalid_redirect_uri (the metadata_policy bounds the derived client)", body["error"])
	}
}
