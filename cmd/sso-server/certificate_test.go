package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/config"
)

// TestLoadCertPool_EmptyPathsReturnsEmptyPool proves the helper
// is a silent no-op for an empty / unset trusted_ca_files list —
// callers that care about an empty trust store have to surface
// that themselves (here, the certificate authenticator rejects
// every verify call against an empty pool, which is correct
// fail-closed behavior).
func TestLoadCertPool_EmptyPathsReturnsEmptyPool(t *testing.T) {
	pool, err := loadCertPool(nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pool == nil {
		t.Fatal("pool is nil; want empty pool")
	}
}

// TestLoadCertPool_MissingFileSurfaces — operators who typo a
// path see an error at boot. Silent ignore would ship the server
// with a partial trust store that admits some certs the operator
// thought they had restricted.
func TestLoadCertPool_MissingFileSurfaces(t *testing.T) {
	if _, err := loadCertPool([]string{"/nonexistent/ca.pem"}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// TestLoadCertPool_NoPEMBlocksSurfaces guards against the
// degenerate-but-plausible case where a file exists but contains
// no CERTIFICATE PEM blocks (wrong file path, file truncated,
// PEM stripped during config templating). Operators see the
// mistake at boot rather than at first login attempt.
func TestLoadCertPool_NoPEMBlocksSurfaces(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(tmp, []byte("not a pem file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadCertPool([]string{tmp})
	if err == nil || !strings.Contains(err.Error(), "no CERTIFICATE PEM blocks") {
		t.Fatalf("err = %v; want no-blocks error", err)
	}
}

// TestLoadCertPool_GoodCertLoads proves the happy path: a
// self-signed CA written to disk produces a pool that verifies
// a cert signed by the CA. Verify is the load-bearing accessor
// here — Subjects() is deprecated for forward compatibility
// with system roots.
func TestLoadCertPool_GoodCertLoads(t *testing.T) {
	pemBytes, ca := makeSelfSignedCAPEM(t, "test-ca")
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := loadCertPool([]string{path})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if _, err := ca.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("self-signed CA failed to verify against loaded pool: %v", err)
	}
}

// TestBuildAuthenticators_CertificateWiresTrustedCAs proves the
// reference config's TrustedCAFiles aren't silently ignored. The
// previous wiring hardcoded x509.NewCertPool() so every operator
// who set trusted_ca_files in YAML watched their certs get
// rejected with no log signal — this asserts the values flow
// through the loader into the registered authenticator.
func TestBuildAuthenticators_CertificateWiresTrustedCAs(t *testing.T) {
	pemBytes, _ := makeSelfSignedCAPEM(t, "wire-test-ca")
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Authenticators.Certificate = &config.CertificateConfig{
		Enabled:        true,
		TrustedCAFiles: []string{path},
	}
	auths, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	found := false
	for _, a := range auths {
		if a.Name() == "certificate" {
			found = true
		}
	}
	if !found {
		t.Fatal("certificate authenticator not registered when Enabled=true with valid TrustedCAFiles")
	}
}

// TestBuildAuthenticators_CertificateBadCAGetsSkipped proves the
// helper's "fail loud" behavior at the cmd boundary: a typo'd CA
// path leaves the authenticator out of the registry (logger
// records the error). The alternative — register with an empty
// pool — would accept zero certs in production, which is the
// silent-ship-broken trap loadCertPool exists to prevent.
func TestBuildAuthenticators_CertificateBadCAGetsSkipped(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.Certificate = &config.CertificateConfig{
		Enabled:        true,
		TrustedCAFiles: []string{"/no/such/ca.pem"},
	}
	auths, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	for _, a := range auths {
		if a.Name() == "certificate" {
			t.Fatal("certificate authenticator registered despite missing CA file")
		}
	}
}

// makeSelfSignedCAPEM generates a fresh self-signed CA cert and
// returns its PEM encoding plus the cert. Test-only helper.
func makeSelfSignedCAPEM(t *testing.T, cn string) ([]byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageCertSign,
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return out, parsed
}
