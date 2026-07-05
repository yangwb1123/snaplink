package securityverify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// Shared test helpers for the workload-identity core + GCP preset tests
// (this file, workload_identity_gcp_test.go, jwks_http_source_test.go): a
// throwaway RSA keypair signer + a fake HTTPS JWKS endpoint (httptest — NOT
// a mock of our own code, a real HTTP server), matching how
// shared/security/spiffe_svid_test.go builds real keys for the SPIFFE path.

// genWITestKey generates a throwaway 2048-bit RSA key and its public core.JWK
// (RS256 — the alg every workload-identity preset defaults to).
func genWITestKey(t *testing.T, kid string) (*rsa.PrivateKey, core.JWK) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	eb := big.NewInt(int64(priv.E)).Bytes()
	jwk := core.JWK{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(eb),
	}
	return priv, jwk
}

// signWITestToken signs an RS256 compact JWS for claims under kid.
func signWITestToken(t *testing.T, priv *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksTestServer serves {"keys":[...]} at its root — a fake cloud JWKS
// endpoint, standard net/http/httptest (not a mock of our own code).
func jwksTestServer(t *testing.T, keys ...core.JWK) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(srv.Close)
	return srv
}

const (
	testWIIssuer   = "https://issuer.example.test"
	testWIAudience = "https://sso.example.test"
)

func testWIMapper(claims map[string]any) (*WorkloadIdentity, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errors.New("missing sub")
	}
	return &WorkloadIdentity{Subject: sub}, nil
}

func newTestValidator(t *testing.T, jwksURL string) *WorkloadIdentityValidator {
	t.Helper()
	v, err := NewWorkloadIdentityValidator("test", testWIIssuer, NewHTTPJWKSSource(jwksURL), testWIMapper)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return v
}

func baseWIClaims(sub string, exp time.Duration) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": testWIIssuer,
		"sub": sub,
		"aud": testWIAudience,
		"iat": now.Unix(),
		"exp": now.Add(exp).Unix(),
	}
}

func TestWorkloadIdentityValidator_HappyPath(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk)
	v := newTestValidator(t, srv.URL)

	tok := signWITestToken(t, priv, "k1", baseWIClaims("workload-1", time.Hour))
	id, err := v.Validate(context.Background(), tok, testWIAudience)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.Subject != "workload-1" {
		t.Errorf("subject = %q, want workload-1", id.Subject)
	}
	if id.Provider != CloudProvider("test") {
		t.Errorf("provider = %q, want test", id.Provider)
	}
}

func TestWorkloadIdentityValidator_WrongAudienceRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk)
	v := newTestValidator(t, srv.URL)

	tok := signWITestToken(t, priv, "k1", baseWIClaims("workload-1", time.Hour))
	if _, err := v.Validate(context.Background(), tok, "https://someone-else.example"); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("wrong aud: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestWorkloadIdentityValidator_WrongIssuerRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk)
	v := newTestValidator(t, srv.URL)

	claims := baseWIClaims("workload-1", time.Hour)
	claims["iss"] = "https://a-different-issuer.example"
	tok := signWITestToken(t, priv, "k1", claims)
	if _, err := v.Validate(context.Background(), tok, testWIAudience); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("wrong iss: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestWorkloadIdentityValidator_ExpiredRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk)
	v := newTestValidator(t, srv.URL)

	tok := signWITestToken(t, priv, "k1", baseWIClaims("workload-1", -time.Hour))
	if _, err := v.Validate(context.Background(), tok, testWIAudience); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("expired: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestWorkloadIdentityValidator_BadSignatureRejected(t *testing.T) {
	t.Parallel()
	_, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk) // JWKS only knows k1's PUBLIC key.
	v := newTestValidator(t, srv.URL)

	otherPriv, _ := genWITestKey(t, "k1") // same kid, DIFFERENT private key.
	tok := signWITestToken(t, otherPriv, "k1", baseWIClaims("workload-1", time.Hour))
	if _, err := v.Validate(context.Background(), tok, testWIAudience); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("forged signature: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestWorkloadIdentityValidator_MapperFailureRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk)
	v := newTestValidator(t, srv.URL)

	claims := baseWIClaims("", time.Hour) // testWIMapper rejects an empty sub.
	tok := signWITestToken(t, priv, "k1", claims)
	if _, err := v.Validate(context.Background(), tok, testWIAudience); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("mapper failure: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestWorkloadIdentityValidator_EmptyExpectedAudienceRejected(t *testing.T) {
	t.Parallel()
	priv, jwk := genWITestKey(t, "k1")
	srv := jwksTestServer(t, jwk)
	v := newTestValidator(t, srv.URL)

	tok := signWITestToken(t, priv, "k1", baseWIClaims("workload-1", time.Hour))
	if _, err := v.Validate(context.Background(), tok, ""); !errors.Is(err, ErrWorkloadIdentityInvalid) {
		t.Fatalf("empty expectedAudience: err = %v, want ErrWorkloadIdentityInvalid", err)
	}
}

func TestNewWorkloadIdentityValidator_RequiresFields(t *testing.T) {
	t.Parallel()
	src := NewHTTPJWKSSource("https://example.test/jwks")
	cases := []struct {
		name   string
		issuer string
		src    JWKSSource
		mapper claimsMapper
	}{
		{"", testWIIssuer, src, testWIMapper},
		{"test", "", src, testWIMapper},
		{"test", testWIIssuer, nil, testWIMapper},
		{"test", testWIIssuer, src, nil},
	}
	for _, c := range cases {
		if _, err := NewWorkloadIdentityValidator(c.name, c.issuer, c.src, c.mapper); err == nil {
			t.Errorf("NewWorkloadIdentityValidator(%q, %q, src=%v, mapper=%v) = nil error, want rejection",
				c.name, c.issuer, c.src != nil, c.mapper != nil)
		}
	}
}

func TestWorkloadIdentityValidator_Name(t *testing.T) {
	t.Parallel()
	v := newTestValidator(t, "https://example.test/jwks")
	if v.Name() != "test" {
		t.Errorf("Name() = %q, want test", v.Name())
	}
}
