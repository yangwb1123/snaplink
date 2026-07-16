package extauthz

import (
	"crypto/x509"
	"encoding/pem"
	"net/url"
)

// parsePeerCertificate decodes Envoy's URL-encoded PEM peer certificate
// (AttributeContext.Source.Certificate, documented as "encoded in URL and
// PEM format") into an *x509.Certificate. Returns nil on any failure
// (empty, non-cert PEM, parse error) — a nil cert means "no verified client
// cert", which the seam treats as the absence of mTLS material. Fail-safe:
// a malformed cert can only FAIL an mTLS sender-constraint (DENY), never
// satisfy one.
//
// We try the URL-unescaped form FIRST (the documented encoding), then the
// raw string as a fallback. The raw fallback matters because url.Query
// unescaping is LOSSY on un-escaped PEM: a '+' in the base64 body decodes
// to a space, corrupting the block. So we never trust a single transform —
// we PEM-decode each candidate and use the first that yields a CERTIFICATE.
func parsePeerCertificate(s string) *x509.Certificate {
	if s == "" {
		return nil
	}
	candidates := make([]string, 0, 2)
	if decoded, err := url.QueryUnescape(s); err == nil && decoded != s {
		// Only add the unescaped form when it actually changed something;
		// when s has no escapes, decoded == s and the raw candidate covers it.
		candidates = append(candidates, decoded)
	}
	candidates = append(candidates, s)

	for _, c := range candidates {
		if cert := certFromPEM(c); cert != nil {
			return cert
		}
	}
	return nil
}

// certFromPEM decodes a single PEM CERTIFICATE block to an *x509.Certificate,
// or nil if c is not a parseable CERTIFICATE PEM.
func certFromPEM(c string) *x509.Certificate {
	block, _ := pem.Decode([]byte(c))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}
