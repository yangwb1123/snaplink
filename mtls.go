package sso

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"

)
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

// applyPairwiseSubject computes the pairwise sub for (client, localSub)
// and persists the reverse mapping in the wired store. Returns the
// pairwise sub when the client opted in AND the store is wired;
// returns localSub unchanged otherwise. Called at every issuance
// path that mints a token whose sub claim the RP will see.
//
// Fail-open: when the store's MapPairwise fails, the function still
// returns the computed pairwise sub but logs the error via the
// supplied error sink. The token MINTS with the pairwise sub —
// resource-side lookups will fail (`invalid_token`) until the next
// successful map. The alternative (fail-closed) would block
// issuance, which is worse than a token whose userinfo path
