package sso_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	mtlsClient   = "mtls-client"
	mtlsUser     = "u-mtls"
	mtlsSecret   = "mtls-secret"
	mtlsPassword = "pw"
)

// loadTestCert generates a fresh self-signed Ed25519 cert at test
// time. The cert is unverified — we only need its DER form for the
// thumbprint and to inject into requests. Generating runtime avoids
// hard-coding a PEM blob that's brittle to validate manually.
func loadTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "snaplink-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// staticCertExtractor is the test-side mTLS extractor that returns
// a fixed cert regardless of request. Lets us simulate mTLS without
// standing up an HTTPS server with client-cert auth.
type staticCertExtractor struct{ cert *x509.Certificate }

func (s staticCertExtractor) ExtractClientCert(_ *http.Request) (*x509.Certificate, bool) {
	if s.cert == nil {
		return nil, false
	}
	return s.cert, true
}

func newMTLSHarness(t *testing.T, withExtractor bool) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	cert := loadTestCert(t)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: mtlsUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: mtlsClient, Secret: mtlsSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != mtlsPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: mtlsUser, Provider: "password"}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withExtractor {
		opts = append(opts, sso.WithClientCertExtractor(staticCertExtractor{cert: cert}))
	}
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, cert
}

func TestMTLSBound_StampsCnfX5TS256(t *testing.T) {
	srv, cert := newMTLSHarness(t, true)
	form := "grant_type=client_credentials&client_id=" + mtlsClient + "&client_secret=" + mtlsSecret
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	payload := decodeAccessTokenPayload(t, access)
	cnf, ok := payload["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("cnf missing: %v", payload)
	}
	got, _ := cnf["x5t#S256"].(string)
	expectedSum := sha256.Sum256(cert.Raw)
	want := base64.RawURLEncoding.EncodeToString(expectedSum[:])
	if got != want {
		t.Errorf("cnf.x5t#S256 = %q want %q", got, want)
	}
	// Token type stays Bearer — RFC 8705 doesn't introduce a new type.
	if out["token_type"] != "Bearer" {
		t.Errorf("token_type = %v want Bearer (mTLS keeps Bearer)", out["token_type"])
	}
}

func TestMTLSBound_NoBindingWithoutExtractor(t *testing.T) {
	srv, _ := newMTLSHarness(t, false)
	form := "grant_type=client_credentials&client_id=" + mtlsClient + "&client_secret=" + mtlsSecret
	resp, _ := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form))
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	payload := decodeAccessTokenPayload(t, access)
	if _, ok := payload["cnf"]; ok {
		t.Errorf("cnf unexpectedly present without extractor wired: %v", payload["cnf"])
	}
}

func TestMTLSBound_DiscoveryFlagFlipsWithExtractor(t *testing.T) {
	srv, _ := newMTLSHarness(t, true)
	resp, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if v, _ := doc["tls_client_certificate_bound_access_tokens"].(bool); !v {
		t.Errorf("tls_client_certificate_bound_access_tokens = %v want true", doc["tls_client_certificate_bound_access_tokens"])
	}
}

func TestMTLSBound_DiscoveryOmitsWithoutExtractor(t *testing.T) {
	srv, _ := newMTLSHarness(t, false)
	resp, _ := http.Get(srv.URL + "/.well-known/openid-configuration")
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if _, present := doc["tls_client_certificate_bound_access_tokens"]; present {
		t.Errorf("flag leaked when extractor not wired")
	}
}

// Ensure imports stay live even if other files drift.
var _ = bytes.MinRead
