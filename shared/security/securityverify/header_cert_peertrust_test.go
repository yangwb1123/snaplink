package securityverify_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/security/peertrust"
	"github.com/yangwb1123/snaplink/shared/security/securityverify"
)

func genCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func certReq(t *testing.T, remoteAddr, headerVal string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://sso.example/token", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.RemoteAddr = remoteAddr
	r.Header.Set("X-SSL-Client-Cert", headerVal)
	return r
}

func peerChecker(t *testing.T, cidrs ...string) *peertrust.Checker {
	t.Helper()
	c, err := peertrust.NewChecker(cidrs)
	if err != nil {
		t.Fatalf("NewChecker(%v): %v", cidrs, err)
	}
	return c
}

func TestHeaderClientCertExtractor_PeerTrust_TrustedPeerParsesCert(t *testing.T) {
	t.Parallel()
	ext := securityverify.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	ext.PeerTrust = peerChecker(t, "10.0.0.0/8")
	escaped := url.QueryEscape(genCertPEM(t))

	cert, ok := ext.ExtractClientCert(certReq(t, "10.0.0.7:34712", escaped))
	if !ok {
		t.Fatal("trusted peer: extraction failed")
	}
	if cert.Subject.CommonName != "client.example" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
}

func TestHeaderClientCertExtractor_PeerTrust_UntrustedPeerYieldsNoCert(t *testing.T) {
	t.Parallel()
	// A peer outside the trusted CIDRs forged the cert header itself. The
	// extractor must return the exact no-cert outcome — issuance falls back
	// to an unbound token, and a bound token at a resource takes the normal
	// invalid_token failure path (no new oracle; see the sender-constraint
	// HTTP test in test/).
	ext := securityverify.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	ext.PeerTrust = peerChecker(t, "10.0.0.0/8")
	escaped := url.QueryEscape(genCertPEM(t))

	if cert, ok := ext.ExtractClientCert(certReq(t, "203.0.113.9:34712", escaped)); ok || cert != nil {
		t.Fatalf("untrusted peer: got (%v, %v), want (nil, false)", cert, ok)
	}
}

func TestHeaderClientCertExtractor_NilPeerTrust_LegacyHeaderTrust(t *testing.T) {
	t.Parallel()
	// Unset knob (nil checker) must stay byte-identical to the legacy
	// trust-the-header behavior.
	ext := securityverify.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	escaped := url.QueryEscape(genCertPEM(t))

	if _, ok := ext.ExtractClientCert(certReq(t, "203.0.113.9:34712", escaped)); !ok {
		t.Fatal("nil PeerTrust: extraction failed, want legacy success")
	}
}
