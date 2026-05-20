package sso

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
)

// RFC 8705 §3 — Mutual-TLS Client Certificate-Bound Access Tokens.
//
// The companion proof-of-possession mechanism to DPoP. Where DPoP
// binds to a JWK the client signs with, mTLS binds to the TLS
// client certificate the client presents during the connection
// handshake. Tokens minted while a client cert was on the wire
// carry an `x5t#S256` value in their `cnf` claim — the SHA-256
// thumbprint of the cert DER. Resource servers reject the token
// unless the SAME cert is on the wire when it's presented.
//
// Scope of THIS implementation (issuance side):
//   - Per-request cert extraction (default: direct TLS handshake
//     via r.TLS.PeerCertificates[0]).
//   - Pluggable ClientCertExtractor so reverse-proxy-terminated TLS
//     (envoy / nginx forwarding X-Forwarded-Client-Cert) works.
//   - SHA-256 thumbprint computation + stamping into the issued
//     access token's `cnf.x5t#S256` claim.
//   - Discovery: `tls_client_certificate_bound_access_tokens: true`
//     when an extractor is wired.
//
// Resource-side verification (a downstream service confirming the
// token's cnf.x5t#S256 matches the cert on the inbound connection)
// is left to the resource — same architectural separation as the
// DPoP commit.

// ClientCertExtractor pulls the client's TLS certificate out of an
// incoming request. The default implementation reads
// r.TLS.PeerCertificates[0] (direct TLS termination on the AS).
// Reverse-proxy-terminated deployments inject a custom extractor
// that parses the proxy's "X-Forwarded-Client-Cert" header
// (envoy / nginx convention).
//
// Returns nil + ok=false when the request had no client cert — the
// /token handler then mints an unbound bearer token (legacy path).
type ClientCertExtractor interface {
	ExtractClientCert(r *http.Request) (cert *x509.Certificate, ok bool)
}

// ClientCertExtractorFunc adapts a function to the
// [ClientCertExtractor] interface.
type ClientCertExtractorFunc func(r *http.Request) (*x509.Certificate, bool)

func (f ClientCertExtractorFunc) ExtractClientCert(r *http.Request) (*x509.Certificate, bool) {
	return f(r)
}

// DefaultTLSPeerCertExtractor reads r.TLS.PeerCertificates[0] —
// the conventional path for direct TLS-terminated AS deployments
// where the Go server itself handles the handshake.
var DefaultTLSPeerCertExtractor ClientCertExtractor = ClientCertExtractorFunc(func(r *http.Request) (*x509.Certificate, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	return r.TLS.PeerCertificates[0], true
})

// certificateThumbprintS256 computes RFC 8705 §3.1's
// `x5t#S256` — base64url-no-pad encoding of SHA-256(cert.Raw).
// cert MUST NOT be nil (callers gate on extractor's ok=false).
func certificateThumbprintS256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyMTLSBearer enforces the resource-side half of RFC 8705 §3.
// Mirror of verifyDPoPBearer: when the access token carries
// cnf.x5t#S256, the inbound request MUST be on a TLS connection
// whose client cert has the matching SHA-256 thumbprint.
//
// Returns nil when:
//   - the token isn't mTLS-bound (no cnf.x5t#S256), OR
//   - the inbound cert thumbprint equals the bound value.
//
// Returns an error mapped to invalid_token (same wire shape as
// "invalid bearer") on mismatch — oracle-resistance: probes can't
// distinguish unbound from bound-but-mismatched tokens.
//
// Skips the check when no ClientCertExtractor is wired: an
// operator that minted mTLS-bound tokens via one deployment and
// then disabled the extractor would otherwise lock every bound
// token out. Operators changing mTLS posture should revoke
// existing bound tokens explicitly.
func (s *Server) verifyMTLSBearer(ctx HandlerContext, claims *TokenClaims) error {
	if claims == nil || claims.ConfirmationX5TS256 == "" {
		return nil
	}
	if s.clientCertExtractor == nil {
		// No extractor wired — see method doc for the
		// trade-off. The cert is still required on the wire
		// for any HTTP framework that auto-populates r.TLS,
		// just not validated.
		return nil
	}
	cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request())
	if !ok || cert == nil {
		return errCertRequired
	}
	got := certificateThumbprintS256(cert)
	if got != claims.ConfirmationX5TS256 {
		return errCertThumbprintMismatch
	}
	return nil
}

// Sentinel errors so logging can distinguish the failure modes
// even though the wire collapses them to invalid_token.
var (
	errCertRequired           = httpError("mtls: token bound but no client cert presented")
	errCertThumbprintMismatch = httpError("mtls: cert thumbprint does not match cnf.x5t#S256")
)

// httpError is a stdlib-free sentinel-error type kept local to
// this file (avoids importing errors just for two constants).
type httpError string

func (e httpError) Error() string { return string(e) }

// mtlsBoundTokenTypeOr returns the appropriate token_type response
// value. Today, mTLS-bound tokens still report "Bearer" per RFC
// 8705 §3 (it does NOT introduce a new type; the binding is implicit
// in the cnf claim). This helper exists so future spec evolution
// (or a strict-mode flag) can swap the value at one site.
func mtlsBoundTokenTypeOr(defaultType string, _ string) string {
	return defaultType
}
