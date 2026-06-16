package security_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/snaplink/sso/security"
)

// genSelfSignedCert mints a real (self-signed) leaf certificate so the
// extractor parses genuine DER, not a hand-rolled byte string.
func genSelfSignedCert(t *testing.T) (der []byte, pemBlock []byte) {
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
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemBlock = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return der, pemBlock
}

func reqWith(headerName, value string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "https://sso.example/token", nil)
	if headerName != "" {
		r.Header.Set(headerName, value)
	}
	return r
}

func TestHeaderClientCertExtractor_URLPEM(t *testing.T) {
	t.Parallel()
	_, pemBlock := genSelfSignedCert(t)
	// NewHeaderClientCertExtractor defaults to URLPEM (nginx / ALB).
	ext := security.NewHeaderClientCertExtractor("X-SSL-Client-Cert")
	escaped := url.QueryEscape(string(pemBlock))

	cert, ok := ext.ExtractClientCert(reqWith("X-SSL-Client-Cert", escaped))
	if !ok {
		t.Fatal("URLPEM extraction failed")
	}
	if cert.Subject.CommonName != "client.example" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
}

func TestHeaderClientCertExtractor_RawPEM(t *testing.T) {
	t.Parallel()
	_, pemBlock := genSelfSignedCert(t)
	ext := &security.HeaderClientCertExtractor{
		HeaderName: "Ssl-Client-Cert",
		Encoding:   security.HeaderCertEncodingPEM,
	}
	cert, ok := ext.ExtractClientCert(reqWith("Ssl-Client-Cert", string(pemBlock)))
	if !ok {
		t.Fatal("raw PEM extraction failed")
	}
	if cert.Subject.CommonName != "client.example" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
}

func TestHeaderClientCertExtractor_Base64DER(t *testing.T) {
	t.Parallel()
	der, _ := genSelfSignedCert(t)
	ext := &security.HeaderClientCertExtractor{
		HeaderName: "X-Edge-Cert",
		Encoding:   security.HeaderCertEncodingBase64DER,
	}
	b64 := base64.StdEncoding.EncodeToString(der)
	cert, ok := ext.ExtractClientCert(reqWith("X-Edge-Cert", b64))
	if !ok {
		t.Fatal("base64-DER extraction failed")
	}
	if cert.Subject.CommonName != "client.example" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
}

// Every failure path returns (nil,false) — the /token handler then
// issues an unbound token, identical to a client that sent no cert.
func TestHeaderClientCertExtractor_FailurePaths(t *testing.T) {
	t.Parallel()
	_, pemBlock := genSelfSignedCert(t)

	cases := []struct {
		name string
		ext  *security.HeaderClientCertExtractor
		req  *http.Request
	}{
		{
			name: "nil extractor",
			ext:  nil,
			req:  reqWith("X-SSL-Client-Cert", url.QueryEscape(string(pemBlock))),
		},
		{
			name: "nil request",
			ext:  security.NewHeaderClientCertExtractor("X-SSL-Client-Cert"),
			req:  nil,
		},
		{
			name: "empty header name",
			ext:  &security.HeaderClientCertExtractor{HeaderName: "", Encoding: security.HeaderCertEncodingURLPEM},
			req:  reqWith("X-SSL-Client-Cert", url.QueryEscape(string(pemBlock))),
		},
		{
			name: "header absent",
			ext:  security.NewHeaderClientCertExtractor("X-SSL-Client-Cert"),
			req:  reqWith("", ""),
		},
		{
			name: "bad url-escape",
			ext:  security.NewHeaderClientCertExtractor("X-SSL-Client-Cert"),
			req:  reqWith("X-SSL-Client-Cert", "%zz-not-valid-escape"),
		},
		{
			name: "non-PEM value",
			ext:  security.NewHeaderClientCertExtractor("X-SSL-Client-Cert"),
			req:  reqWith("X-SSL-Client-Cert", url.QueryEscape("not a pem block")),
		},
		{
			name: "PEM with wrong block type",
			ext:  &security.HeaderClientCertExtractor{HeaderName: "X-SSL-Client-Cert", Encoding: security.HeaderCertEncodingPEM},
			req: reqWith("X-SSL-Client-Cert", string(pem.EncodeToMemory(&pem.Block{
				Type: "PRIVATE KEY", Bytes: []byte("junk"),
			}))),
		},
		{
			name: "valid PEM block but invalid DER",
			ext:  &security.HeaderClientCertExtractor{HeaderName: "X-SSL-Client-Cert", Encoding: security.HeaderCertEncodingPEM},
			req: reqWith("X-SSL-Client-Cert", string(pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: []byte("not-valid-der-bytes"),
			}))),
		},
		{
			name: "bad base64-DER",
			ext:  &security.HeaderClientCertExtractor{HeaderName: "X-Edge-Cert", Encoding: security.HeaderCertEncodingBase64DER},
			req:  reqWith("X-Edge-Cert", "!!!not-base64!!!"),
		},
		{
			name: "unknown encoding",
			ext:  &security.HeaderClientCertExtractor{HeaderName: "X-Edge-Cert", Encoding: security.HeaderCertEncoding(99)},
			req:  reqWith("X-Edge-Cert", url.QueryEscape(string(pemBlock))),
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert, ok := tc.ext.ExtractClientCert(tc.req)
			if ok || cert != nil {
				t.Errorf("%s: got (%v, %v), want (nil, false)", tc.name, cert, ok)
			}
		})
	}
}
