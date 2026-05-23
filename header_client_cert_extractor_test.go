package sso

import (
	"github.com/snaplink/sso/security"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func newTestClientCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, der
}

func TestHeaderClientCertExtractor_URLPEMNginx(t *testing.T) {
	cert, der := newTestClientCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	ex := security.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-SSL-Client-Cert", url.QueryEscape(string(pemBytes)))

	got, ok := ex.ExtractClientCert(r)
	if !ok {
		t.Fatal("extractor returned ok=false on valid url-pem header")
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("serial mismatch: got %v want %v", got.SerialNumber, cert.SerialNumber)
	}
	if certificateThumbprintS256(got) != certificateThumbprintS256(cert) {
		t.Fatal("thumbprint mismatch after url-pem round trip")
	}
}

func TestHeaderClientCertExtractor_PEMApache(t *testing.T) {
	cert, der := newTestClientCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	ex := &security.HeaderClientCertExtractor{HeaderName: "Ssl-Client-Cert", Encoding: security.HeaderCertEncodingPEM}
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("Ssl-Client-Cert", string(pemBytes))

	got, ok := ex.ExtractClientCert(r)
	if !ok {
		t.Fatal("extractor returned ok=false on valid pem header")
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("serial mismatch")
	}
}

func TestHeaderClientCertExtractor_Base64DER(t *testing.T) {
	cert, der := newTestClientCert(t)

	ex := &security.HeaderClientCertExtractor{HeaderName: "X-Client-Cert-DER", Encoding: security.HeaderCertEncodingBase64DER}
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert-DER", base64.StdEncoding.EncodeToString(der))

	got, ok := ex.ExtractClientCert(r)
	if !ok {
		t.Fatal("extractor returned ok=false on valid base64-der header")
	}
	if got.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("serial mismatch")
	}
}

func TestHeaderClientCertExtractor_MissingHeaderFallsOpen(t *testing.T) {
	ex := security.NewHeaderClientCertExtractor("X-Client-Cert")
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	cert, ok := ex.ExtractClientCert(r)
	if ok || cert != nil {
		t.Fatal("absent header must yield (nil, false) — same wire outcome as no-cert client")
	}
}

func TestHeaderClientCertExtractor_MalformedPEM(t *testing.T) {
	ex := &security.HeaderClientCertExtractor{HeaderName: "X-Client-Cert", Encoding: security.HeaderCertEncodingPEM}
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "not a pem block")
	cert, ok := ex.ExtractClientCert(r)
	if ok || cert != nil {
		t.Fatal("malformed pem must not produce a cert — header forgery / proxy misconfig should fail closed")
	}
}

func TestHeaderClientCertExtractor_BadBase64(t *testing.T) {
	ex := &security.HeaderClientCertExtractor{HeaderName: "X-Client-Cert", Encoding: security.HeaderCertEncodingBase64DER}
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "!!! invalid base64 !!!")
	cert, ok := ex.ExtractClientCert(r)
	if ok || cert != nil {
		t.Fatal("invalid base64 must not produce a cert")
	}
}

func TestHeaderClientCertExtractor_BadURLEscape(t *testing.T) {
	ex := security.NewHeaderClientCertExtractor("X-Client-Cert")
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "%ZZ-not-url-escaped")
	cert, ok := ex.ExtractClientCert(r)
	if ok || cert != nil {
		t.Fatal("invalid url-encoding must not produce a cert")
	}
}

func TestHeaderClientCertExtractor_NilSafe(t *testing.T) {
	var ex *security.HeaderClientCertExtractor
	cert, ok := ex.ExtractClientCert(httptest.NewRequest(http.MethodPost, "/token", nil))
	if ok || cert != nil {
		t.Fatal("nil extractor must not panic and must return (nil, false)")
	}
}

func TestHeaderClientCertExtractor_EmptyHeaderName(t *testing.T) {
	ex := &security.HeaderClientCertExtractor{}
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "any value")
	cert, ok := ex.ExtractClientCert(r)
	if ok || cert != nil {
		t.Fatal("empty HeaderName must yield (nil, false) — misconfig should be inert, not panic")
	}
}

func TestHeaderClientCertExtractor_NotACertificatePEM(t *testing.T) {
	wrong := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a cert")})
	ex := &security.HeaderClientCertExtractor{HeaderName: "X-Client-Cert", Encoding: security.HeaderCertEncodingPEM}
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", string(wrong))
	cert, ok := ex.ExtractClientCert(r)
	if ok || cert != nil {
		t.Fatal("non-CERTIFICATE PEM type must be rejected")
	}
}
