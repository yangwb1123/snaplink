package sso

import (
	"net/http"

	"github.com/snaplink/sso/security"
)

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
