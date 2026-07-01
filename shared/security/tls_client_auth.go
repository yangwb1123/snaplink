// Package security provides TLS client certificate verification for
// RFC 8705 §2 tls_client_auth and self_signed_tls client authentication
// methods at the /token, /introspect, /revoke, and /par endpoints.
package security

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"strings"
)

// VerifyTLSClientAuth checks whether the presented client certificate
// satisfies the registered TLS constraint fields per RFC 8705 §2.
// Each non-empty constraint is AND-ed: when both SubjectDN and SANDNS
// are set, the cert MUST match BOTH. Returns nil on success or a
// descriptive error.
func VerifyTLSClientAuth(cert *x509.Certificate, subjectDN, sanDNS, sanEmail, sanURI string) error {
	if subjectDN != "" {
		if !matchSubjectDN(cert.Subject.String(), subjectDN) {
			return errors.New("tls_client_auth: client cert Subject DN does not match registered TLSClientAuthSubjectDN")
		}
	}
	if sanDNS != "" {
		if !matchSANDNS(cert, sanDNS) {
			return errors.New("tls_client_auth: client cert SAN DNS does not match registered TLSClientAuthSANDNS")
		}
	}
	if sanEmail != "" {
		if !matchSANEmail(cert, sanEmail) {
			return errors.New("tls_client_auth: client cert SAN email does not match registered TLSClientAuthSANEmail")
		}
	}
	if sanURI != "" {
		if !matchSANURI(cert, sanURI) {
			return errors.New("tls_client_auth: client cert SAN URI does not match registered TLSClientAuthSANURI")
		}
	}
	return nil
}

// CertPublicKeyMatchesJWK reports whether the cert's public key matches
// the raw key material in the given JWK fields.
func CertPublicKeyMatchesJWK(cert *x509.Certificate, kty, crv, x, y, n, e string) (bool, error) {
	if cert == nil {
		return false, errors.New("nil certificate")
	}
	pub := cert.PublicKey
	switch kty {
	case "RSA":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return false, nil
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			return false, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil {
			return false, err
		}
		gotN := new(big.Int).SetBytes(nBytes)
		gotE := decodePublicExponent(eBytes)
		return rsaPub.N.Cmp(gotN) == 0 && rsaPub.E == gotE, nil
	case "EC":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return false, nil
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return false, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(y)
		if err != nil {
			return false, err
		}
		gotX := new(big.Int).SetBytes(xBytes)
		gotY := new(big.Int).SetBytes(yBytes)
		return ecPub.X.Cmp(gotX) == 0 && ecPub.Y.Cmp(gotY) == 0, nil
	case "OKP":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return false, nil
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(x)
		if err != nil {
			return false, err
		}
		return string(edPub) == string(xBytes), nil
	}
	return false, errors.New("unsupported JWK kty: " + kty)
}

// IsTLSClientCert returns true when the request carries a verified TLS
// client certificate (either from the TLS layer itself or from a
// trusted proxy header via the configured extractor). This is a
// convenience predicate for the token handler's mTLS auth path.
func IsTLSClientCert(cert *x509.Certificate) bool {
	return cert != nil
}

func decodePublicExponent(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	var e int
	for _, v := range b {
		e = (e << 8) | int(v)
	}
	return e
}

// matchSubjectDN compares two RFC 4514 DN strings after normalization.
func matchSubjectDN(got, expected string) bool {
	return normalizeDN(got) == normalizeDN(expected)
}

// normalizeDN strips extra whitespace around = and , delimiters.
func normalizeDN(dn string) string {
	var b strings.Builder
	for _, r := range dn {
		switch {
		case r == '=':
			b.WriteRune(r)
		case r == ',' || r == '+':
			b.WriteRune(r)
		case r == ' ':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// matchSANDNS checks if any DNS SAN entry matches expected
// (case-insensitive per RFC 5280 §4.2.1.6).
func matchSANDNS(cert *x509.Certificate, expected string) bool {
	expected = strings.ToLower(expected)
	for _, dns := range cert.DNSNames {
		if strings.ToLower(dns) == expected {
			return true
		}
	}
	return false
}

// matchSANEmail checks if any rfc822Name SAN entry matches expected.
func matchSANEmail(cert *x509.Certificate, expected string) bool {
	at := strings.LastIndex(expected, "@")
	if at < 0 {
		return false
	}
	expLocal := expected[:at]
	expHost := strings.ToLower(expected[at+1:])
	for _, email := range cert.EmailAddresses {
		at2 := strings.LastIndex(email, "@")
		if at2 < 0 {
			continue
		}
		if strings.ToLower(email[at2+1:]) != expHost {
			continue
		}
		if email[:at2] == expLocal {
			return true
		}
	}
	return false
}

// matchSANURI checks if any URI SAN entry matches expected
// (byte-exact match per RFC 5280 §4.2.1.6).
func matchSANURI(cert *x509.Certificate, expected string) bool {
	expectedURI := expected
	for _, uri := range cert.URIs {
		if uri.String() == expectedURI {
			return true
		}
	}
	return false
}

// SANFromCert extracts the first SAN of each type from the cert
// for diagnostic logging.
func SANFromCert(cert *x509.Certificate) (dns, email, uri string, ips []net.IP) {
	if len(cert.DNSNames) > 0 {
		dns = cert.DNSNames[0]
	}
	if len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	}
	if len(cert.URIs) > 0 {
		uri = cert.URIs[0].String()
	}
	ips = cert.IPAddresses
	return
}

// compile-time check that crypto interfaces are satisfied.
var _ crypto.PublicKey = (*rsa.PublicKey)(nil)
var _ crypto.PublicKey = (*ecdsa.PublicKey)(nil)
var _ crypto.PublicKey = (ed25519.PublicKey)(nil)
