package sso

import (
	"net/http"
	"strings"

	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// SAMLAssertionValidator validates an RFC 7522 SAML 2.0 bearer assertion.
// Implementations parse and validate the base64-encoded SAML assertion XML,
// verifying signature, audience, conditions, and SubjectConfirmation method.
// On success they return the SAML NameID (the subject's federated identifier).
// Every failure collapses to the same opaque error (oracle-leak hardening).
type SAMLAssertionValidator = tokengrant.SAMLAssertionValidator

// WithSAML2BearerGrant enables the RFC 7522 SAML 2.0 Bearer Assertion Grant
// by wiring an assertion validator. When wired, clients can present a
// base64-encoded SAML 2.0 assertion to /token using
// grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer and receive an
// access token bound to the SAML NameID-mapped local user.
//
// The validator must decode, parse, and validate the SAML assertion
// (signature, audience, conditions, SubjectConfirmation method=Bearer).
// On success it returns the NameID subject. Every failure collapses to
// invalid_grant (oracle-leak hardening).
//
// Nil validator is a no-op (the grant stays disabled).
func WithSAML2BearerGrant(validator SAMLAssertionValidator) Option {
	return func(s *Server) {
		if validator == nil {
			return
		}
		s.saml2BearerValidator = validator
		if s.customGrantHandlers == nil {
			s.customGrantHandlers = make(map[string]oauth.GrantHandler)
		}
		s.customGrantHandlers[core.GrantTypeSAML2Bearer] = &saml2BearerHandler{server: s}
	}
}

// saml2BearerHandler is an oauth.GrantHandler that delegates to
// tokengrant.HandleSAML2BearerGrant, using the server as the deps
// provider.
type saml2BearerHandler struct {
	server *Server
}

func (h *saml2BearerHandler) GrantType() string {
	return core.GrantTypeSAML2Bearer
}

func (h *saml2BearerHandler) Handle(ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	assertion := req.Assertion
	if assertion == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var scopes []string
	if req.Scope != "" {
		scopes = strings.Split(req.Scope, " ")
	}
	tokengrant.HandleSAML2BearerGrant(h.server, ctx, client, assertion, scopes, req.Resource, dpopJKT, mtlsX5T)
}
