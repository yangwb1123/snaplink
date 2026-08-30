package tokengrant

import (
	"net/http"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oauth/scoperegistry"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ClientCredentialsDeps is what HandleClientCredentialsGrant needs. *sso.Server
// satisfies it via accessors_token_grant.go with a compile-time guard there.
type ClientCredentialsDeps interface {
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	DPoPTokenTypeOr(defaultType, jkt string) string
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
	// ScopeRegistry returns the wired global scope registry (nil = unwired
	// no-op, the default-off byte-compat baseline).
	ScopeRegistry() scoperegistry.Registry
}

// HandleClientCredentialsGrant processes the RFC 6749 §4.4 client_credentials
// grant. Behavior is byte-identical to the prior inline dispatcher branch. The
// subject IS the client, so no end-user auth event (no AuthTime/AMR), no refresh
// token, and no id_token are issued.
func HandleClientCredentialsGrant(d ClientCredentialsDeps, ctx core.HandlerContext, client *core.Client, scopes, resources []string, dpopJKT, mtlsX5T string) {
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	// Scope authorization (RFC 6749 §3.3). The client is already authenticated by
	// the dispatcher (HTTP Basic > body creds), so this gate is not a pre-auth
	// probe. Reject an out-of-allowlist scope with 400 invalid_scope; default an
	// empty request to the client's AllowedScopes so the token carries its
	// entitled scope. Empty allowlist = unrestricted (byte-identical pass-through).
	grantCCScopes, ccScopeErr := oauth.GrantedScopes(scopes, client)
	if ccScopeErr != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
		return
	}
	// Global scope registry (opt-in): the rule-4 defaulted set (empty request,
	// client allowlist minus openid) and the requested set both resolve HERE, so
	// this post-resolution check is the effective-scope point for this branch.
	if scoperegistry.RejectUnregistered(ctx, d.ScopeRegistry(), grantCCScopes) {
		return
	}
	// client_credentials: subject IS the client, so ClientID = Sub.
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID: client.ID, Resources: resources, ClientID: client.ID,
		TenantID:            client.TenantID,
		TTL:                 client.AccessTokenTTL,
		ConfirmationJKT:     dpopJKT,
		ConfirmationX5TS256: mtlsX5T,
		NotAfter:            MTLSCertNotAfterFrom(ctx),
		ServingRegion:       servingRegionFrom(ctx),
	}, grantCCScopes)
	if err != nil {
		d.LogErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
		writeTokenIssueError(ctx, err)
		return
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, client.ID)
	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyAccessToken:   token.AccessToken,
		core.KeyTokenType:     d.DPoPTokenTypeOr(token.TokenType, dpopJKT),
		core.KeyExpiresIn:     token.ExpiresIn,
		core.KeyScope:         token.Scope,
		core.KeyTokenStrategy: strategy,
	})
}

func writeTokenIssueError(ctx core.HandlerContext, err error) {
	if status, code, ok := core.AuthHookHTTPError(err); ok {
		ctx.JSON(status, core.ErrorBody(code))
		return
	}
	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
}
