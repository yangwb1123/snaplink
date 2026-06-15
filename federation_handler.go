package sso

import (
	"net/http"

	"github.com/snaplink/sso/federation"
	"github.com/snaplink/sso/middleware"
)
func (s *Server) BuildOPMetadata(ctx HandlerContext, base string) federation.OPFederationMetadata {
	cfg := s.buildOIDCConfiguration(ctx, base)
	return federation.OPFederationMetadata{
		Issuer:                            cfg.Issuer,
		AuthorizationEndpoint:             cfg.AuthorizationEndpoint,
		TokenEndpoint:                     cfg.TokenEndpoint,
		UserinfoEndpoint:                  cfg.UserInfoEndpoint,
		JWKSURI:                           cfg.JWKSURI,
		RegistrationEndpoint:              cfg.RegistrationEndpoint,
		ResponseTypesSupported:            cfg.ResponseTypesSupported,
		SubjectTypesSupported:             cfg.SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  cfg.IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   cfg.ScopesSupported,
		TokenEndpointAuthMethodsSupported: cfg.TokenEndpointAuthMethodsSupported,
		CodeChallengeMethodsSupported:     cfg.CodeChallengeMethodsSupported,
	}
}

// handleFederationEntityConfig delegates to the hexagonal federation handler
// (*Server satisfies federation.Deps via accessors.go). Only mounted when
// WithFederationEntity is wired.
func (s *Server) handleFederationEntityConfig(ctx HandlerContext) {
	federation.HandleEntityConfiguration(s, ctx)
}

// handleFederationFetch delegates to the hexagonal OpenID Federation 1.0 §8
// Federation Fetch handler (*Server satisfies federation.FetchDeps via
// accessors.go). Only mounted when WithFederationEntity is wired AND
// subordinates are configured (this server acts as a federation SUPERIOR) —
// byte-identical off otherwise.
func (s *Server) handleFederationFetch(ctx HandlerContext) {
	federation.HandleFederationFetch(s, ctx)
}

// requestBaseURL delegates to middleware.BaseURL — see that function
// for the X-Forwarded-Proto / X-Forwarded-Host edge trust contract.
func requestBaseURL(r *http.Request) string { return middleware.BaseURL(r) }
