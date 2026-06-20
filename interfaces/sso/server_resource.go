package sso

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"github.com/snaplink/sso/shared/security"
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

// ProtectedResourceMetadata configures the RFC 9728 OAuth 2.0 Protected
// Resource Metadata document. All fields are optional overrides — sensible
// values are derived from server state at request time (resource = request
// base URL, authorization_servers = [issuer], jwks_uri, scopes, signing algs,
// mTLS/DPoP capability). Wire it with WithProtectedResourceMetadata; nil leaves
// the /.well-known/oauth-protected-resource route unmounted (byte-identical).
type ProtectedResourceMetadata struct {
	// Resource overrides the protected-resource identifier. Empty = the request
	// base URL (the common case: this server IS the resource).
	Resource string
	// AuthorizationServers overrides the AS issuer list. Empty = [server issuer].
	AuthorizationServers []string
	// ResourceName / ResourceDocumentation are optional human-facing fields.
	ResourceName          string
	ResourceDocumentation string
}

// protectedResourceMetadataDoc is the RFC 9728 §2 document. Fields are omitted
// when empty so the document advertises only what the server actually supports.
type protectedResourceMetadataDoc struct {
	Resource                          string   `json:"resource"`
	AuthorizationServers              []string `json:"authorization_servers,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported            []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`
	TLSClientCertificateBound         bool     `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	DPoPSigningAlgValuesSupported     []string `json:"dpop_signing_alg_values_supported,omitempty"`
	ResourceName                      string   `json:"resource_name,omitempty"`
	ResourceDocumentation             string   `json:"resource_documentation,omitempty"`
}

// WithProtectedResourceMetadata mounts the RFC 9728 OAuth 2.0 Protected Resource
// Metadata endpoint at /.well-known/oauth-protected-resource. Clients —
// especially MCP / AI-agent clients following the protected-resource discovery
// flow — fetch it to learn which authorization server issues tokens for this
// resource, the JWKS, supported scopes, and token-binding requirements. The
// document is derived from server state; prm supplies optional overrides. Not
// wired ⇒ the route is absent (byte-identical).
func WithProtectedResourceMetadata(prm ProtectedResourceMetadata) Option {
	return func(s *Server) {
		cp := prm
		s.protectedResourceMetadata = &cp
	}
}

// handleProtectedResourceMetadata serves the RFC 9728 document. Public (no
// auth) like the other /.well-known/* discovery endpoints. Derived per request
// so multi-host deployments get the right base URL.
func (s *Server) handleProtectedResourceMetadata(ctx HandlerContext) {
	prm := s.protectedResourceMetadata
	base := requestBaseURL(ctx.Request())

	resource := base
	if prm.Resource != "" {
		resource = prm.Resource
	}
	authServers := prm.AuthorizationServers
	if len(authServers) == 0 {
		authServers = []string{s.resolveIssuer(ctx)}
	}

	doc := protectedResourceMetadataDoc{
		Resource:                          resource,
		AuthorizationServers:              authServers,
		JWKSURI:                           base + PathJWKS,
		BearerMethodsSupported:            []string{"header"},
		ResourceSigningAlgValuesSupported: s.SigningAlgValues(ctx.Request().Context()),
		ResourceName:                      prm.ResourceName,
		ResourceDocumentation:             prm.ResourceDocumentation,
	}
	if snap := s.discoverySnapshot(ctx.Request().Context()); snap != nil && len(snap.scopes) > 0 {
		doc.ScopesSupported = snap.scopes
	}
	// Token-binding capability mirrors the discovery doc: mTLS-bound when a
	// client-cert extractor is wired, DPoP algs when DPoP can be used (the
	// asymmetric JWS allowlist).
	if s.clientCertExtractor != nil {
		doc.TLSClientCertificateBound = true
	}
	doc.DPoPSigningAlgValuesSupported = security.AsymmetricJWSAlgValues()

	ctx.JSON(http.StatusOK, doc)
}
