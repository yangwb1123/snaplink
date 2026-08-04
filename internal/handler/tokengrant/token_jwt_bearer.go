package tokengrant

import (
	"net/http"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// DefaultJWTBearerClockSkew is the default clock skew tolerance for the
// RFC 7523 JWT Bearer assertion validation.
const DefaultJWTBearerClockSkew = 30

// JWTBearerGrantDeps is what HandleJWTBearerGrant needs. *sso.Server satisfies
// it via accessors handlers with a compile-time guard there.
type JWTBearerGrantDeps interface {
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	DPoPTokenTypeOr(defaultType, jkt string) string
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
	// JWTBearerAssertionValidator returns the configured JWT assertion
	// validator for RFC 7523; nil means the grant is not supported.
	JWTBearerAssertionValidator() JWTAssertionValidator
}

// JWTAssertionValidator validates an RFC 7523 JWT bearer assertion.
type JWTAssertionValidator interface {
	// ValidateAssertion parses and validates the JWT assertion, returning
	// the issuer and subject on success. Every failure collapses to the
	// same opaque error (oracle-leak hardening).
	ValidateAssertion(ctx core.HandlerContext, assertion string) (issuer, subject string, err error)
}

// HandleJWTBearerGrant processes the RFC 7523 §2.1 JWT Bearer Token Grant.
// The client presents a signed JWT assertion which is validated against a
// configurable trust anchor. On success an access token is issued for the
// subject identified by the assertion's `sub` claim.
func HandleJWTBearerGrant(d JWTBearerGrantDeps, ctx core.HandlerContext, client *core.Client, assertion string, scopes []string, resources []string, dpopJKT, mtlsX5T string) {
	subject, ok := validateJWTBearerAssertion(d, ctx, assertion)
	if !ok {
		return
	}
	if lifecycleGrantBlocked(d, ctx, subject) {
		return
	}
	strategy, ti, ok := resolveIssuerForJWTBearer(d, ctx, client)
	if !ok {
		return
	}
	grantScopes, ok := authorizeJWTBearerScopes(ctx, scopes, client)
	if !ok {
		return
	}
	issueJWTBearerToken(d, ctx, client, subject, strategy, ti, grantScopes, resources, dpopJKT, mtlsX5T)
}

// validateJWTBearerAssertion validates the JWT assertion and returns the subject.
// Returns false when the response is already written.
func validateJWTBearerAssertion(d JWTBearerGrantDeps, ctx core.HandlerContext, assertion string) (string, bool) {
	validator := d.JWTBearerAssertionValidator()
	if validator == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrUnsupportedGrantType))
		return "", false
	}
	issuer, subject, err := validator.ValidateAssertion(ctx, assertion)
	if err != nil {
		d.LogErrorCtx(ctx, "jwt-bearer assertion validation failed", "issuer", issuer, "error", err)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return "", false
	}
	return subject, true
}

// resolveIssuerForJWTBearer resolves a token issuer for the client.
// Returns false when the response is already written.
func resolveIssuerForJWTBearer(d JWTBearerGrantDeps, ctx core.HandlerContext, client *core.Client) (string, core.TokenIssuer, bool) {
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return "", nil, false
	}
	return strategy, ti, true
}

// authorizeJWTBearerScopes validates the requested scopes against the client's allowlist.
// Returns false when the response is already written.
func authorizeJWTBearerScopes(ctx core.HandlerContext, scopes []string, client *core.Client) ([]string, bool) {
	grantScopes, scopeErr := oauth.GrantedScopes(scopes, client)
	if scopeErr != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return nil, false
	}
	return grantScopes, true
}

// issueJWTBearerToken mints the access token and writes the response.
func issueJWTBearerToken(d JWTBearerGrantDeps, ctx core.HandlerContext, client *core.Client, subject, strategy string, ti core.TokenIssuer, scopes, resources []string, dpopJKT, mtlsX5T string) {
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
		d.LogErrorCtx(ctx, "jwt-bearer token issuance failed", "strategy", strategy, "error", err)
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
