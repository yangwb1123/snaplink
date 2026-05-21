package sso

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/url"
	"strings"
)

// HeaderCertEncoding describes how a TLS-terminating reverse proxy
// has encoded the forwarded client certificate in its HTTP header.
type HeaderCertEncoding int

const (
	// HeaderCertEncodingURLPEM expects a URL-encoded PEM block — the
	// dominant convention for nginx (`proxy_set_header X-SSL-Client-Cert
	// $ssl_client_escaped_cert;`) and AWS ALB mTLS passthrough
	// (`X-Amzn-Mtls-Clientcert`).
	HeaderCertEncodingURLPEM HeaderCertEncoding = iota
	// HeaderCertEncodingPEM expects a raw PEM block as-is. Apache
	// mod_ssl's `SSL_CLIENT_CERT` ships this format when newlines
	// survive the proxy hop.
	HeaderCertEncodingPEM
	// HeaderCertEncodingBase64DER expects standard base64 of the raw
	// DER bytes — most compact wire form, used by some custom edges.
	HeaderCertEncodingBase64DER
)

// HeaderClientCertExtractor implements [ClientCertExtractor] over an
// HTTP header populated by a TLS-terminating reverse proxy. Use this
// when the AS sits behind nginx / Apache / AWS ALB / k8s ingress and
// the edge has been configured to forward the verified client cert.
//
// Trust boundary: the configured header MUST be stripped from every
// inbound request that did not transit the trusted edge. A public
// attacker who can forge the header can otherwise mint mTLS-bound
// tokens for an arbitrary certificate without ever holding the
// matching key. Same threat model as X-Forwarded-For — only honor
// when received from a known proxy IP. The companion
// [TrustedProxies] middleware enforces this at the network layer.
//
// Common deployments:
//   - nginx (X-SSL-Client-Cert, $ssl_client_escaped_cert): URLPEM
//   - AWS ALB mTLS (X-Amzn-Mtls-Clientcert): URLPEM
//   - Apache mod_ssl (Ssl-Client-Cert / X-SSL-Client-Cert): PEM
//   - openresty lua-resty-jwt edge: configurable; commonly URLPEM
//
// For envoy XFCC (RFC 9440) parse the structured value upstream and
// supply a custom [ClientCertExtractor] — XFCC carries Hash=, Cert=,
// Chain=, By= as a list, which this single-value extractor cannot
// decode on its own.
type HeaderClientCertExtractor struct {
	HeaderName string
	Encoding   HeaderCertEncoding
}

// NewHeaderClientCertExtractor returns an extractor configured for
// the most common nginx / AWS ALB deployment (URL-encoded PEM block).
// Override Encoding directly for other layouts.
func NewHeaderClientCertExtractor(headerName string) *HeaderClientCertExtractor {
	return &HeaderClientCertExtractor{
		HeaderName: headerName,
		Encoding:   HeaderCertEncodingURLPEM,
	}
}

// ExtractClientCert implements [ClientCertExtractor]. Returns
// (nil, false) on any decode / parse failure — the /token handler
// falls back to issuing an unbound bearer token, the same wire
// outcome as a client that simply did not present a cert.
func (h *HeaderClientCertExtractor) ExtractClientCert(r *http.Request) (*x509.Certificate, bool) {
	if h == nil || r == nil || h.HeaderName == "" {
		return nil, false
	}
	raw := r.Header.Get(h.HeaderName)
	if raw == "" {
		return nil, false
	}
	der, err := decodeHeaderCert(raw, h.Encoding)
	if err != nil || len(der) == 0 {
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, false
	}
	return cert, true
}

func decodeHeaderCert(raw string, enc HeaderCertEncoding) ([]byte, error) {
	switch enc {
	case HeaderCertEncodingURLPEM:
		unescaped, err := url.QueryUnescape(raw)
		if err != nil {
			return nil, err
		}
		return decodePEMCertBlock(unescaped), nil
	case HeaderCertEncodingPEM:
		return decodePEMCertBlock(raw), nil
	case HeaderCertEncodingBase64DER:
		return base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	default:
		return nil, nil
	}
}

func decodePEMCertBlock(s string) []byte {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return block.Bytes
}
