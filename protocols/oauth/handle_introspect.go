package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// ClientAssertionTypeJWTBearer is the RFC 7521 §4.2 URN for
// JWT Bearer client assertions. Pulled local so handle_introspect /
// handle_par / handle_revoke can branch on it without importing
// back to root.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// IntrospectDeps is what HandleIntrospect needs. *sso.Server
// satisfies it via accessor methods.
type IntrospectDeps interface {
	ClientStoreAccessor() core.ClientStore
	JTIReplayStore() security.JTIReplayStore
	TokenIssuers() map[string]core.TokenIssuer
	RefreshTokenStore() RefreshTokenStore
	ResolveIssuer(ctx core.HandlerContext) string
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
}

// introspectRequest is the bound form/JSON body for /token/introspect.
type introspectRequest struct {
	Token               string `json:"token"`
	TokenTypeHint       string `json:"token_type_hint"` // "access_token" | "refresh_token"
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	ClientAssertion     string `json:"client_assertion"`      // RFC 7521 + 7523
	ClientAssertionType string `json:"client_assertion_type"` // RFC 7521 + 7523
}

// HandleIntrospect implements RFC 7662 OAuth 2.0 Token Introspection.
// Returns active state + standard metadata claims for a presented
// access or refresh token. Inactive tokens return {active: false}
// only, with no extra metadata — §2.2 mandates this to limit
// oracle leakage.
//
// Auth: the introspecting client authenticates with client_id +
// client_secret (Basic auth or form body). Per §2.1 any registered
// active client may introspect — production deployments that want
// stronger isolation should layer an authorization middleware that
// checks a custom "introspect" scope or role on the client.
func HandleIntrospect(d IntrospectDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	if d.ClientStoreAccessor() == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	var req introspectRequest
	if err := BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		// HTTP Basic auth takes precedence over body fields when
		// present — matches the RFC 6749 §2.3.1 recommendation.
		req.ClientID = id
		req.ClientSecret = secret
	}

	clientStore := d.ClientStoreAccessor()

	// Client auth: the assertion branch and the secret-creds branch both
	// write the identical 401 invalid_client on failure (oracle-leak
	// collapse). handled==true means a response was already written.
	if handled := authenticateIntrospectClient(d, clientStore, ctx, &req); handled {
		return
	}

	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	if body, ok := resolveIntrospection(d, ctx, req.Token, req.TokenTypeHint); ok {
		ctx.JSON(http.StatusOK, body)
		return
	}

	// Unknown / expired / revoked → §2.2 mandates {active: false} only.
	ctx.JSON(http.StatusOK, map[string]any{core.KeyActive: false})
}

// authenticateIntrospectClient runs the hint-independent client-auth gate
// for /token/introspect. The RFC 7521/7523 JWT-assertion branch and the
// secret-creds branch BOTH emit the identical 401 invalid_client on failure
// — the oracle-leak collapse stays byte-for-byte. A wrong
// client_assertion_type still yields 400 invalid_request. Returns
// handled=true when it has already written the response (caller must return
// immediately); false lets the caller proceed.
func authenticateIntrospectClient(d IntrospectDeps, clientStore core.ClientStore, ctx core.HandlerContext, req *introspectRequest) (handled bool) {
	// RFC 7521/7523 JWT bearer client auth on /token/introspect.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return true
		}
		assertedID, err := d.VerifyJWTClientAssertion(
			ctx.Request().Context(),
			req.ClientAssertion,
			req.ClientID,
			d.ResolveIssuer(ctx),
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return true
		}
		req.ClientID = assertedID
		// Bypass the secret-based authenticate path entirely: JWT
		// assertion stands in for the secret per RFC 7521 §4.2.
		// Still validate the tenant + active gates below via a
		// minimal client lookup so a deactivated client can't
		// introspect.
		c, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil || c == nil || !c.Active || !tenant.ClientOK(ctx, c) {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return true
		}
		return false
	}
	if err := authenticateIntrospectionClient(clientStore, ctx, req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return true
	}
	return false
}

// resolveIntrospection applies the hint-driven try-order and returns the
// first populated body. Resolution order is hint-driven: when the hint is
// "refresh_token" try the refresh store first to avoid an unnecessary
// access-token signature check, but ALWAYS fall back to the other tier so a
// wrong hint doesn't mark a valid token inactive.
func resolveIntrospection(d IntrospectDeps, ctx core.HandlerContext, token, hint string) (map[string]any, bool) {
	if hint == "refresh_token" {
		if body, ok := introspectRefresh(d.RefreshTokenStore(), ctx, token); ok {
			return body, true
		}
		if body, ok := introspectAccess(d, ctx, token); ok {
			return body, true
		}
		return nil, false
	}
	if body, ok := introspectAccess(d, ctx, token); ok {
		return body, true
	}
	if body, ok := introspectRefresh(d.RefreshTokenStore(), ctx, token); ok {
		return body, true
	}
	return nil, false
}

// introspectAccess validates the token as an access token via every
// registered issuer. Returns a populated metadata body on success.
func introspectAccess(d IntrospectDeps, ctx core.HandlerContext, token string) (map[string]any, bool) {
	if len(d.TokenIssuers()) == 0 {
		return nil, false
	}
	claims, issuerName, err := d.ValidateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil {
		return nil, false
	}
	body := map[string]any{
		core.KeyActive:    true,
		core.KeyTokenType: core.TokenTypeBearer,
		core.KeySub:       claims.Subject,
		core.KeyIss:       claims.Issuer,
		core.KeyTokenHint: "access_token",
		core.KeyStrategy:  issuerName,
	}
	populateAccessIntrospectionBody(body, claims)
	return body, true
}

// populateAccessIntrospectionBody copies the optional RFC 7662 / RFC 9068
// claims onto an already-active access-token body. Purely additive: it
// carries NO early-return / auth-gate semantics — the ValidateAnyToken auth
// gate stays in introspectAccess.
func populateAccessIntrospectionBody(body map[string]any, claims *core.TokenClaims) {
	if !claims.ExpiresAt.IsZero() {
		body[core.KeyExp] = claims.ExpiresAt.Unix()
	}
	if !claims.IssuedAt.IsZero() {
		body[core.KeyIat] = claims.IssuedAt.Unix()
	}
	if !claims.NotBefore.IsZero() {
		body[core.KeyNbf] = claims.NotBefore.Unix()
	}
	if len(claims.Audience) > 0 {
		body[core.KeyAud] = claims.Audience
	}
	// RFC 9068 §2.2 supplies a first-class `client_id` claim. Prefer
	// it; fall back to the first audience entry for older tokens or
	// non-RFC-9068 issuers (per RFC 7662 §2.2 the field is optional).
	switch {
	case claims.ClientID != "":
		body[core.KeyClientID] = claims.ClientID
	case len(claims.Audience) > 0:
		body[core.KeyClientID] = claims.Audience[0]
	}
	if len(claims.Scopes) > 0 {
		body[core.KeyScope] = strings.Join(claims.Scopes, " ")
	}
	// RFC 9068 §2.2 jti — useful for replay tracking on the
	// introspecting resource server. Same goes for auth_time / acr
	// / amr which let downstream policy reason about how the user
	// authenticated.
	if claims.JTI != "" {
		body[core.KeyJTI] = claims.JTI
	}
	if !claims.AuthTime.IsZero() {
		body[core.KeyAuthTime] = claims.AuthTime.Unix()
	}
	if claims.ACR != "" {
		body[core.KeyACR] = claims.ACR
	}
	if len(claims.AMR) > 0 {
		body[core.KeyAMR] = claims.AMR
	}
}

// introspectRefresh queries the optional RefreshTokenInspector.
// Returns (nil, false) when the store doesn't implement the
// inspector extension OR the token is unknown / expired.
func introspectRefresh(store RefreshTokenStore, ctx core.HandlerContext, token string) (map[string]any, bool) {
	insp, ok := store.(RefreshTokenInspector)
	if !ok {
		return nil, false
	}
	info, err := insp.Inspect(ctx.Request().Context(), token)
	if err != nil || info == nil {
		return nil, false
	}
	body := map[string]any{
		core.KeyActive:    true,
		core.KeyTokenType: core.TokenTypeBearer,
		core.KeySub:       info.UserID,
		core.KeyClientID:  info.ClientID,
		core.KeyTokenHint: "refresh_token",
	}
	if !info.ExpiresAt.IsZero() {
		body[core.KeyExp] = info.ExpiresAt.Unix()
	}
	if !info.IssuedAt.IsZero() {
		body[core.KeyIat] = info.IssuedAt.Unix()
	}
	if len(info.Scopes) > 0 {
		body[core.KeyScope] = strings.Join(info.Scopes, " ")
	}
	return body, true
}

// authenticateIntrospectionClient verifies the introspecting client's
// credentials via the existing client store. Returns nil on success.
func authenticateIntrospectionClient(clientStore core.ClientStore, ctx core.HandlerContext, id, secret string) error {
	if id == "" || secret == "" {
		return errors.New("missing client credentials")
	}
	client, err := clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		return err
	}
	if !client.Active {
		return errors.New("inactive client")
	}
	if !tenant.ClientOK(ctx, client) {
		return errors.New("tenant mismatch")
	}
	return clientStore.ValidateSecret(ctx.Request().Context(), id, secret)
}
