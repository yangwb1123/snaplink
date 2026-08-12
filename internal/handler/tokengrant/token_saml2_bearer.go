package tokengrant

import (
	"encoding/base64"
	"net/http"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oauth/scoperegistry"
	"github.com/yangwb1123/snaplink/shared/core"
)

// SAML2BearerGrantDeps is what HandleSAML2BearerGrant needs.
// *sso.Server satisfies it via accessors handlers with a compile-time
// guard there.
type SAML2BearerGrantDeps interface {
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	DPoPTokenTypeOr(defaultType, jkt string) string
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
	// SAML2AssertionValidator returns the configured SAML 2.0 assertion
	// validator for RFC 7522; nil means the grant is not supported.
	SAML2AssertionValidator() SAMLAssertionValidator
	// ScopeRegistry returns the wired global scope registry (nil = unwired
	// no-op, the default-off byte-compat baseline).
	ScopeRegistry() scoperegistry.Registry
}

// SAMLAssertionValidator validates an RFC 7522 SAML 2.0 bearer assertion.
type SAMLAssertionValidator interface {
	// ValidateAssertion parses and validates the base64-encoded SAML 2.0
	// assertion, returning the subject NameID on success. Every failure
	// collapses to the same opaque error (oracle-leak hardening).
	ValidateAssertion(ctx core.HandlerContext, assertionB64 string) (subject string, err error)
}

// HandleSAML2BearerGrant processes the RFC 7522 SAML 2.0 Bearer Assertion
// Token Grant. The client presents a base64-encoded SAML 2.0 assertion which
// is decoded, signature-verified, and validated (audience, conditions,
// SubjectConfirmation method=Bearer). On success an access token is issued
// for the subject identified by the assertion's NameID.
func HandleSAML2BearerGrant(d SAML2BearerGrantDeps, ctx core.HandlerContext, client *core.Client, assertion string, scopes []string, resources []string, dpopJKT, mtlsX5T string) {
	subject, ok := validateSAML2Assertion(d, ctx, assertion)
	if !ok {
		return
	}
	if lifecycleGrantBlocked(d, ctx, subject) {
		return
	}
	strategy, ti, ok := resolveIssuerForSAML2(d, ctx, client)
	if !ok {
		return
	}
	grantScopes, ok := authorizeSAML2Scopes(ctx, scopes, client)
	if !ok {
		return
	}
	// Global scope registry (opt-in): the GrantedScopes result (incl. the
	// rule-4 default for an empty request) is the effective set for this
	// branch — post-resolution, pre-issuance. Request-borne SAML2 scopes were
	// already covered by the dispatch seam (saml2_bearer rides
	// customGrantHandlers, which runs after it); this check closes the
	// store-bound/defaulted gap.
	if scoperegistry.RejectUnregistered(ctx, d.ScopeRegistry(), grantScopes) {
		return
	}
	issueSAML2Token(d, ctx, client, subject, strategy, ti, grantScopes, resources, dpopJKT, mtlsX5T)
}

// validateSAML2Assertion validates the SAML 2.0 assertion and returns the
// subject NameID. Returns false when the response is already written.
func validateSAML2Assertion(d SAML2BearerGrantDeps, ctx core.HandlerContext, assertion string) (string, bool) {
	validator := d.SAML2AssertionValidator()
	if validator == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrUnsupportedGrantType))
		return "", false
	}

	// The assertion is base64-encoded SAML XML. Fail early on decode
	// errors before handing to the validator.
	if _, err := base64.StdEncoding.DecodeString(assertion); err != nil {
		d.LogErrorCtx(ctx, "saml2-bearer: assertion base64 decode failed", "error", err)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSAMLAssertionInvalid))
		return "", false
	}

	subject, err := validator.ValidateAssertion(ctx, assertion)
	if err != nil {
		d.LogErrorCtx(ctx, "saml2-bearer: assertion validation failed", "error", err)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return "", false
	}
	return subject, true
}

// resolveIssuerForSAML2 resolves a token issuer for the client.
// Returns false when the response is already written.
func resolveIssuerForSAML2(d SAML2BearerGrantDeps, ctx core.HandlerContext, client *core.Client) (string, core.TokenIssuer, bool) {
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return "", nil, false
	}
	return strategy, ti, true
}

// authorizeSAML2Scopes validates the requested scopes against the client's
// allowlist. Returns false when the response is already written.
func authorizeSAML2Scopes(ctx core.HandlerContext, scopes []string, client *core.Client) ([]string, bool) {
	grantScopes, scopeErr := oauth.GrantedScopes(scopes, client)
	if scopeErr != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return nil, false
	}
	return grantScopes, true
}

// issueSAML2Token mints the access token and writes the response.
func issueSAML2Token(d SAML2BearerGrantDeps, ctx core.HandlerContext, client *core.Client, subject, strategy string, ti core.TokenIssuer, scopes, resources []string, dpopJKT, mtlsX5T string) {
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID:                  subject,
		Resources:           resources,
		ClientID:            client.ID,
		TenantID:            client.TenantID,
		TTL:                 client.AccessTokenTTL,
		ConfirmationJKT:     dpopJKT,
		ConfirmationX5TS256: mtlsX5T,
		ServingRegion:       servingRegionFrom(ctx),
	}, scopes)
	if err != nil {
		d.LogErrorCtx(ctx, "saml2-bearer: token issuance failed", "strategy", strategy, "error", err)
		writeTokenIssueError(ctx, err)
		return
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, subject)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyAccessToken: token.AccessToken,
		core.KeyTokenType:   d.DPoPTokenTypeOr(token.TokenType, dpopJKT),
		core.KeyExpiresIn:   token.ExpiresIn,
		core.KeyScope:       token.Scope,
	})
}
