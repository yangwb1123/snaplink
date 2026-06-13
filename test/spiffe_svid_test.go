package ssotest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
)

const (
	svidTrustDomain = "example.org"
	svidAudience    = "https://sso.example/"
	svidSub         = "spiffe://example.org/ns/prod/sa/payments"
	svidClientID    = "mesh-client"
	svidClientSec   = "mesh-secret"
	svidResource    = "https://api.example/v1"
)

// spireKey is a test SPIRE JWT signing key. SPIRE defaults to ES256
// (priv set); a PS256 variant carries rsaPriv instead.
type spireKey struct {
	priv    *ecdsa.PrivateKey
	rsaPriv *rsa.PrivateKey
	alg     string
	kid     string
	jwk     core.JWK
}

// newSpirePS256Key generates an RSA-2048 PS256 SPIRE key — exercising the
// allowlisted PS256 SVID branch end-to-end through /token exchange.
func newSpirePS256Key(t *testing.T, kid string) spireKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	eb := big.NewInt(int64(priv.E)).Bytes()
	return spireKey{
		rsaPriv: priv, alg: "PS256", kid: kid,
		jwk: core.JWK{
			Kty: "RSA", Kid: kid, Use: "sig", Alg: "PS256",
			N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(eb),
		},
	}
}

func newSpireKey(t *testing.T, kid string) spireKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	return spireKey{
		priv: priv, alg: "ES256", kid: kid,
		jwk: core.JWK{
			Kty: "EC", Crv: "P-256", Kid: kid, Use: "sig", Alg: "ES256",
			X: base64.RawURLEncoding.EncodeToString(xb),
			Y: base64.RawURLEncoding.EncodeToString(yb),
		},
	}
}

// mint signs a JWT-SVID with the key's own alg (ES256 or PS256).
// algOverride forges the header alg (e.g. "none").
func (k spireKey) mint(t *testing.T, algOverride string, claims map[string]any) string {
	t.Helper()
	alg := k.alg
	if algOverride != "" {
		alg = algOverride
	}
	header := map[string]any{"alg": alg, "typ": "JWT", "kid": k.kid}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	var sig []byte
	switch alg {
	case "none":
		sig = nil
	case "ES256":
		d := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, k.priv, d[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		sig = out
	case "PS256":
		// Standard PS256 signer (go-jose / golang-jwt / SPIRE): auto/max salt.
		d := sha256.Sum256([]byte(signingInput))
		out, err := rsa.SignPSS(rand.Reader, k.rsaPriv, crypto.SHA256, d[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			t.Fatalf("sign pss: %v", err)
		}
		sig = out
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func svidClaims(sub, aud string) map[string]any {
	now := time.Now()
	return map[string]any{
		"sub": sub, "aud": aud,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
}

// newSPIFFEHarness wires a server whose own local issuer is Ed25519
// (so locally-issued jwt tokens still validate) PLUS a SPIFFE validator
// trusting `key`. wire=false omits the validator (feature-off baseline).
func newSPIFFEHarness(t *testing.T, key spireKey, wire bool) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: svidClientID, Secret: svidClientSec, Active: true,
		TokenStrategy:    "jwt",
		AllowedResources: []string{svidResource},
	})
	localIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	opts := []sso.Option{
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", localIssuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuditRecorder(rec),
	}
	if wire {
		bundle := security.NewStaticJWKS([]core.JWK{key.jwk})
		opts = append(opts, sso.WithSPIFFEJWTSVID(svidTrustDomain, svidAudience, bundle))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func exchangeSVID(t *testing.T, srv *httptest.Server, svid, resource string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":          {svidClientID},
		"client_secret":      {svidClientSec},
		"subject_token":      {svid},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"},
	}
	if resource != "" {
		form.Set("resource", resource)
	}
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSPIFFE_HappyPath_IssuesTokenWithAttributes(t *testing.T) {
	key := newSpireKey(t, "spire-1")
	srv, sink := newSPIFFEHarness(t, key, true)
	svid := key.mint(t, "", svidClaims(svidSub, svidAudience))

	status, body := exchangeSVID(t, srv, svid, svidResource)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %v", body)
	}
	// sub is the spiffe:// id.
	if sub := jwtPayloadField(t, access, "sub"); sub != svidSub {
		t.Errorf("sub = %v want %q", sub, svidSub)
	}
	// RFC 9068 Subject.ClientID — the exchanging client must be stamped.
	if cid := jwtPayloadField(t, access, "client_id"); cid != svidClientID {
		t.Errorf("client_id = %v want %q (RFC 9068 §2.2)", cid, svidClientID)
	}
	// AMR carries the mesh-workload signal.
	amr := jwtPayloadField(t, access, "amr")
	arr, _ := amr.([]any)
	if len(arr) != 1 || arr[0] != "spiffe" {
		t.Errorf("amr = %v want [spiffe]", amr)
	}
	// SPIFFE attributes projected under the issuer's "ext" custom-claims
	// namespace (Subject.Claims → ed25519 payload `ext`).
	ext, _ := jwtPayloadField(t, access, "ext").(map[string]any)
	if ext == nil {
		t.Fatalf("ext claims missing: %v", body)
	}
	if ext[security.AttrSPIFFETrustDomain] != svidTrustDomain {
		t.Errorf("ext.trust_domain = %v", ext[security.AttrSPIFFETrustDomain])
	}
	if ext[security.AttrSPIFFENamespace] != "prod" {
		t.Errorf("ext.namespace = %v", ext[security.AttrSPIFFENamespace])
	}
	if ext[security.AttrSPIFFEServiceAccount] != "payments" {
		t.Errorf("ext.service_account = %v", ext[security.AttrSPIFFEServiceAccount])
	}
	// aud is the exchanged-for resource.
	if aud := jwtPayloadField(t, access, "aud"); aud != svidResource {
		t.Errorf("aud = %v want %q", aud, svidResource)
	}

	// Internal audit event recorded with SPIFFE metadata.
	evts, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventSPIFFEJWTSVIDAccepted})
	if len(evts) != 1 {
		t.Fatalf("want 1 spiffe_jwt_svid_accepted event, got %d", len(evts))
	}
	e := evts[0]
	if e.ActorID != svidSub || e.ClientID != svidClientID {
		t.Errorf("audit actor/client = %q/%q", e.ActorID, e.ClientID)
	}
	if e.Metadata[core.KeySPIFFETrustDomain] != svidTrustDomain ||
		e.Metadata[core.KeySPIFFENamespace] != "prod" ||
		e.Metadata[core.KeySPIFFEServiceAccount] != "payments" {
		t.Errorf("audit metadata = %v", e.Metadata)
	}
}

// TestSPIFFE_PS256HappyPath_IssuesToken exchanges a PS256 JWT-SVID signed
// with the standard auto/max PSS salt end-to-end. Before the verify-side
// salt fix this returned 400 invalid_grant (the auto-salt signature failed
// the hash-length-salt verify), silently breaking the allowlisted PS256 SVID.
func TestSPIFFE_PS256HappyPath_IssuesToken(t *testing.T) {
	key := newSpirePS256Key(t, "spire-ps")
	srv, _ := newSPIFFEHarness(t, key, true)
	svid := key.mint(t, "", svidClaims(svidSub, svidAudience))

	status, body := exchangeSVID(t, srv, svid, svidResource)
	if status != http.StatusOK {
		t.Fatalf("ps256 status=%d body=%v", status, body)
	}
	access, _ := body["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %v", body)
	}
	if sub := jwtPayloadField(t, access, "sub"); sub != svidSub {
		t.Errorf("sub = %v want %q", sub, svidSub)
	}
}

// TestSPIFFE_WeakRSAKeyRejected: a sub-2048-bit trust-bundle RSA key is
// rejected — the SVID it signs gets the SAME 400 invalid_grant (the external
// trust boundary must meet the issued-key modulus floor, RFC 7518 §3.3).
func TestSPIFFE_WeakRSAKeyRejected(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024) // below the 2048-bit floor
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	eb := big.NewInt(int64(priv.E)).Bytes()
	key := spireKey{
		rsaPriv: priv, alg: "PS256", kid: "weak-rsa",
		jwk: core.JWK{
			Kty: "RSA", Kid: "weak-rsa", Use: "sig", Alg: "PS256",
			N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(eb),
		},
	}
	srv, _ := newSPIFFEHarness(t, key, true)
	svid := key.mint(t, "", svidClaims(svidSub, svidAudience))

	status, body := exchangeSVID(t, srv, svid, svidResource)
	if status != http.StatusBadRequest {
		t.Fatalf("weak-rsa status=%d want 400 body=%v", status, body)
	}
	if body["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant (oracle-safe)", body["error"])
	}
}

// TestSPIFFE_SecurityRejections enumerates the attack cases. EACH must
// return the SAME 400 invalid_grant — no oracle distinguishes the cause.
func TestSPIFFE_SecurityRejections(t *testing.T) {
	good := newSpireKey(t, "spire-1")
	attacker := newSpireKey(t, "attacker") // not in the trust bundle

	cases := []struct {
		name string
		svid func(t *testing.T) string
	}{
		{"wrong trust domain", func(t *testing.T) string {
			return good.mint(t, "", svidClaims("spiffe://evil.example/ns/x/sa/y", svidAudience))
		}},
		{"aud mismatch (svid for service-B, exchanged for service-A)", func(t *testing.T) string {
			return good.mint(t, "", svidClaims(svidSub, "https://service-b/"))
		}},
		{"expired svid", func(t *testing.T) string {
			c := svidClaims(svidSub, svidAudience)
			c["iat"] = time.Now().Add(-10 * time.Minute).Unix()
			c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
			return good.mint(t, "", c)
		}},
		{"bad signature (key not in bundle)", func(t *testing.T) string {
			forged := attacker
			forged.kid = good.kid // resolves to good's key; sig won't verify
			return forged.mint(t, "", svidClaims(svidSub, svidAudience))
		}},
		{"alg=none", func(t *testing.T) string {
			return good.mint(t, "none", svidClaims(svidSub, svidAudience))
		}},
		{"malformed spiffe sub", func(t *testing.T) string {
			return good.mint(t, "", svidClaims("https://not-spiffe/x", svidAudience))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newSPIFFEHarness(t, good, true)
			status, body := exchangeSVID(t, srv, tc.svid(t), svidResource)
			if status != http.StatusBadRequest {
				t.Fatalf("%s: status=%d want 400 body=%v", tc.name, status, body)
			}
			if body["error"] != "invalid_grant" {
				t.Errorf("%s: error=%v want invalid_grant (oracle-safe)", tc.name, body["error"])
			}
		})
	}
}

// TestSPIFFE_FeatureOffByteIdentical: with NO validator wired, a valid
// spiffe-sub subject_token is rejected exactly as today (400 invalid_grant),
// byte-identical to the validator being wired but the SVID failing.
func TestSPIFFE_FeatureOffByteIdentical(t *testing.T) {
	key := newSpireKey(t, "spire-1")
	validSVID := key.mint(t, "", svidClaims(svidSub, svidAudience))

	srvOff, _ := newSPIFFEHarness(t, key, false)
	statusOff, bodyOff := exchangeSVID(t, srvOff, validSVID, svidResource)

	// Reference: validator wired but the SVID is for the wrong trust
	// domain (also rejected). Both must be the identical wire response.
	srvOn, _ := newSPIFFEHarness(t, key, true)
	badSVID := key.mint(t, "", svidClaims("spiffe://evil.example/x", svidAudience))
	statusOn, bodyOn := exchangeSVID(t, srvOn, badSVID, svidResource)

	if statusOff != http.StatusBadRequest || statusOn != http.StatusBadRequest {
		t.Fatalf("statuses off=%d on=%d want both 400", statusOff, statusOn)
	}
	if bodyOff["error"] != "invalid_grant" || bodyOn["error"] != "invalid_grant" {
		t.Errorf("errors off=%v on=%v want both invalid_grant", bodyOff["error"], bodyOn["error"])
	}
}

// TestSPIFFE_LocalJWTSubjectTokenUnchanged: a locally-issued jwt
// subject_token still works unchanged even with the SPIFFE validator
// wired — the SVID path is a fallback that only runs after the local path
// fails, so it never intercepts a valid local token.
func TestSPIFFE_LocalJWTSubjectTokenUnchanged(t *testing.T) {
	key := newSpireKey(t, "spire-1")
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: svidClientID, Secret: svidClientSec, Active: true,
		TokenStrategy:    "jwt",
		AllowedResources: []string{svidResource},
	})
	localIssuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	bundle := security.NewStaticJWKS([]core.JWK{key.jwk})
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", localIssuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithSPIFFEJWTSVID(svidTrustDomain, svidAudience, bundle),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	// Mint a normal local access token (subject is a plain user id, not
	// a spiffe:// URI) and exchange it as subject_token_type=jwt.
	local, err := localIssuer.Issue(context.Background(),
		&sso.Subject{ID: "ordinary-user", ClientID: svidClientID}, []string{"read"})
	if err != nil {
		t.Fatalf("mint local: %v", err)
	}

	status, body := exchangeSVID(t, httpSrv, local.AccessToken, svidResource)
	if status != http.StatusOK {
		t.Fatalf("local jwt subject_token status=%d body=%v", status, body)
	}
	if sub := jwtPayloadField(t, body["access_token"].(string), "sub"); sub != "ordinary-user" {
		t.Errorf("sub = %v want ordinary-user (local path, not SVID)", sub)
	}
}
