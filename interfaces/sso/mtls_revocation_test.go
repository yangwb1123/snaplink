package sso_test

// mtls_revocation_test.go covers the RFC 8705 §2 tls_client_auth
// certificate-authentication path combined with a wired
// [sso.WithMTLSRevocationChecker] — the gap identified when auditing
// mTLS: chain/DN/SAN verification alone never checks whether a
// certificate has been revoked. No mocks: a real mutual-TLS connection +
// a stub spi.CertRevocationChecker.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// mtlsRevocationStubChecker is a test-only spi.CertRevocationChecker
// returning canned (revoked, err) values.
type mtlsRevocationStubChecker struct {
	revoked bool
	err     error
}

func (c mtlsRevocationStubChecker) IsRevoked(context.Context, *x509.Certificate) (bool, error) {
	return c.revoked, c.err
}

var _ spi.CertRevocationChecker = mtlsRevocationStubChecker{}

// mtlsRevocationServer wires a client registered for tls_client_auth (no
// DN/SAN constraints, so any presented cert satisfies the binding check —
// isolating the test to the revocation gate) behind a real mutual-TLS
// listener, with checker as the revocation checker.
func mtlsRevocationServer(t *testing.T, checker spi.CertRevocationChecker) (*httptest.Server, tls.Certificate) {
	t.Helper()
	clientCert := rcov2ClientCert(t)

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                      "mtls-auth-client",
		TokenEndpointAuthMethod: sso.ClientAuthTLS,
		TokenStrategy:           "jwt",
		Active:                  true,
		SkipConsent:             true,
	})
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithClientCertExtractor(sso.DefaultTLSPeerCertExtractor),
		sso.WithMTLSRevocationChecker(checker),
	)
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, clientCert
}

func mtlsRevocationTokenRequest(t *testing.T, ts *httptest.Server, cert tls.Certificate) *http.Response {
	t.Helper()
	certPool := x509.NewCertPool()
	certPool.AddCert(ts.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
	}}}
	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {"mtls-auth-client"},
		"scope":      {"read"},
	}
	resp, err := client.Post(ts.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	return resp
}

// TestMTLSRevocation_NotRevoked_Authenticates proves the happy path is
// unaffected: a checker reporting not-revoked still lets tls_client_auth
// succeed. It also exercises denyPublicClientCredentials's mTLS carve-out —
// this client has no Secret and no ClientAssertion, which used to be
// misclassified as "public" and rejected regardless of a successful mTLS
// authentication.
func TestMTLSRevocation_NotRevoked_Authenticates(t *testing.T) {
	t.Parallel()
	ts, cert := mtlsRevocationServer(t, mtlsRevocationStubChecker{revoked: false})
	resp := mtlsRevocationTokenRequest(t, ts, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body := rcov2ReadJSON(t, resp)
		t.Fatalf("status = %d, want 200 for a not-revoked cert; body=%v", resp.StatusCode, body)
	}
}

// TestMTLSRevocation_Revoked_Rejected proves the fail-closed half of the
// contract: a checker reporting revoked=true blocks tls_client_auth even
// though DN/SAN binding (trivially, since none are configured) succeeded.
func TestMTLSRevocation_Revoked_Rejected(t *testing.T) {
	t.Parallel()
	ts, cert := mtlsRevocationServer(t, mtlsRevocationStubChecker{revoked: true})
	resp := mtlsRevocationTokenRequest(t, ts, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a revoked cert", resp.StatusCode)
	}
}

// TestMTLSRevocation_CheckerError_FailsOpen proves the fail-open half: a
// checker error (CRL/OCSP source unreachable) logs and allows rather than
// locking out every mTLS client during an outage.
func TestMTLSRevocation_CheckerError_FailsOpen(t *testing.T) {
	t.Parallel()
	ts, cert := mtlsRevocationServer(t, mtlsRevocationStubChecker{err: errors.New("ocsp responder: timeout")})
	resp := mtlsRevocationTokenRequest(t, ts, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (fail-open) when the revocation checker errors", resp.StatusCode)
	}
}

// TestMTLSRevocation_NoCheckerWired_Authenticates proves the default (no
// [sso.WithMTLSRevocationChecker]) is byte-identical to the historical
// chain+DN/SAN-only behavior.
func TestMTLSRevocation_NoCheckerWired_Authenticates(t *testing.T) {
	t.Parallel()
	ts, cert := mtlsRevocationServer(t, nil)
	resp := mtlsRevocationTokenRequest(t, ts, cert)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 with no revocation checker wired", resp.StatusCode)
	}
}
