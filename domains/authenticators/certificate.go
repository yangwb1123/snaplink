package authenticators

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"
)

// IdentityFromCert extracts an SSO subject identity from a verified client certificate.
// Default behavior: use the Subject CommonName as the user ID and copy the first
// DNS/email SAN entries into attributes. Override to map your own PKI conventions.
type IdentityFromCert func(*x509.Certificate) *sso.Subject

func defaultIdentityFromCert(cert *x509.Certificate) *sso.Subject {
	id := cert.Subject.CommonName
	if id == "" && len(cert.EmailAddresses) > 0 {
		id = cert.EmailAddresses[0]
	}
	if id == "" {
		id = cert.SerialNumber.String()
	}
	claims := map[string]string{
		"cn":     cert.Subject.CommonName,
		"serial": cert.SerialNumber.String(),
		"issuer": cert.Issuer.String(),
	}
	if len(cert.EmailAddresses) > 0 {
		claims["email"] = cert.EmailAddresses[0]
	}
	if len(cert.DNSNames) > 0 {
		claims["dns"] = cert.DNSNames[0]
	}
	return &sso.Subject{ID: subjectPrefixCert + id, Claims: claims}
}

// CertificateAuthenticator authenticates a client via an X.509 certificate
// (think mTLS-style auth without forcing a custom TLS handler). The client
// supplies its certificate as a PEM blob in the credential map; the server
// verifies it against a trusted CA pool and a configurable validation policy.
//
// For true mTLS the certificate would normally come from
// req.TLS.PeerCertificates rather than the credential body — but accepting it
// in the body lets non-TLS callers (CLI tools, IoT gateways behind a TLS
// terminator) authenticate too.
type CertificateAuthenticator struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	keyUsages     []x509.ExtKeyUsage
	identity      IdentityFromCert
	revocation    spi.CertRevocationChecker
	logger        spi.Logger
}

type CertOption func(*CertificateAuthenticator)

func WithCertIntermediates(pool *x509.CertPool) CertOption {
	return func(c *CertificateAuthenticator) { c.intermediates = pool }
}

func WithCertKeyUsages(u ...x509.ExtKeyUsage) CertOption {
	return func(c *CertificateAuthenticator) { c.keyUsages = u }
}

func WithCertIdentity(fn IdentityFromCert) CertOption {
	return func(c *CertificateAuthenticator) { c.identity = fn }
}

// WithCertRevocationChecker checks a certificate's revocation status (CRL,
// OCSP, or any operator-chosen source) after chain/expiry verification
// succeeds. See [spi.CertRevocationChecker]'s doc for the fail-open contract
// on checker errors. Without this option, revocation is never checked — a
// certificate authenticates until it expires, matching this authenticator's
// historical (chain+expiry-only) behavior.
func WithCertRevocationChecker(rc spi.CertRevocationChecker) CertOption {
	return func(c *CertificateAuthenticator) { c.revocation = rc }
}

// WithCertLogger records fail-open revocation-check errors (see
// [WithCertRevocationChecker]). Without a logger, checker errors are
// silently swallowed (still fail-open, just unobserved).
func WithCertLogger(l spi.Logger) CertOption {
	return func(c *CertificateAuthenticator) { c.logger = l }
}

func NewCertificateAuthenticator(roots *x509.CertPool, opts ...CertOption) *CertificateAuthenticator {
	c := &CertificateAuthenticator{
		roots:     roots,
		keyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		identity:  defaultIdentityFromCert,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *CertificateAuthenticator) Name() string { return MethodCertificate }

func (c *CertificateAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	pemBytes := []byte(req.Credential["certificate"])
	if len(pemBytes) == 0 {
		return nil, errors.New("certificate: pem-encoded certificate required")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("certificate: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificate: parse: %w", err)
	}

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: c.intermediates,
		KeyUsages:     c.keyUsages,
		CurrentTime:   time.Now(),
	}); err != nil {
		return nil, fmt.Errorf("certificate: verify: %w", err)
	}
	if c.certRevoked(ctx, cert) {
		return nil, errors.New("certificate: verify: certificate revoked")
	}

	subject := c.identity(cert)
	return &sso.AuthResult{
		UserID:      subject.ID,
		ExternalID:  cert.Subject.CommonName,
		Provider:    c.Name(),
		Attributes:  subject.Claims,
		AuthMethods: []string{AuthMethodX509},
	}, nil
}

// certRevoked reports whether cert is revoked per the configured
// [spi.CertRevocationChecker], fail-open on checker error (see that type's
// doc for why). Kept separate from Authenticate to stay within the
// function-length budget.
func (c *CertificateAuthenticator) certRevoked(ctx context.Context, cert *x509.Certificate) bool {
	if c.revocation == nil {
		return false
	}
	revoked, err := c.revocation.IsRevoked(ctx, cert)
	if err != nil {
		if c.logger != nil {
			c.logger.Error("certificate: revocation check failed, allowing (fail-open)", "error", err.Error())
		}
		return false
	}
	return revoked
}

func (c *CertificateAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("certificate: callback not supported")
}

func (c *CertificateAuthenticator) LoginURL(_ string) string { return "" }
