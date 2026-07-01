package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// PARDeps is what HandlePAR needs. *sso.Server satisfies it via
// accessor methods.
type PARDeps interface {
	ClientStoreAccessor() core.ClientStore
	JTIReplayStore() security.JTIReplayStore
	PARStore() PARStore
	PARTTL() time.Duration
	ResolveIssuer(ctx core.HandlerContext) string
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	SrvLogger() spi.Logger
}

// HandlePAR implements RFC 9126 Pushed Authorization Requests.
// Confidential clients POST their authorization request parameters
// here BEFORE redirecting the user agent, getting back an opaque
// request_uri they then pass to /auth/login. This pre-registration
// pattern:
//
//   - Authenticates the client BEFORE the user-agent redirect (the
//     traditional authorization flow has the AS see the client only
//     AFTER the redirect, when there's nothing to do about a bad
//     request beyond rendering an error).
//   - Removes long auth-request URLs (PKCE + scopes + state +
//     resource + nonce add up fast) that browsers, log files, and
//     proxies all handle poorly.
//   - Prevents request-tampering: nothing in the redirect URL
//     beyond client_id + request_uri can be modified without
//     invalidating the lookup.
//
// Auth: HTTP Basic OR client_id+client_secret form body per
// RFC 6749 §2.3.1 (Basic wins when both present — same precedence
// rule as /token).
func HandlePAR(d PARDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	if d.PARStore() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrPARNotConfigured))
		return
	}
	if d.ClientStoreAccessor() == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	var req parRequestForm
	if err := BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	client, ok := authenticatePARClient(d, ctx, &req)
	if !ok {
		return
	}

	if !validatePARRequestParams(ctx, &req, client) {
		return
	}

	issuePARRequest(d, ctx, &req)
}

// parRequestForm is the wire payload for RFC 9126 Pushed Authorization
// Requests, bound from form body or JSON.
type parRequestForm struct {
	ClientID             string          `json:"client_id"`
	ClientSecret         string          `json:"client_secret"`
	ResponseType         string          `json:"response_type"`
	RedirectURI          string          `json:"redirect_uri"`
	Scope                string          `json:"scope"`
	State                string          `json:"state"`
	Nonce                string          `json:"nonce"`
	CodeChallenge        string          `json:"code_challenge"`
	CodeChallengeMethod  string          `json:"code_challenge_method"`
	Resource             []string        `json:"resource"`
	AuthorizationDetails json.RawMessage `json:"authorization_details"` // RFC 9396
	LoginHint            string          `json:"login_hint"`            // OIDC Core §3.1.2.1
	ResponseMode         string          `json:"response_mode"`         // OIDC Form Post 1.0
	ACRValues            string          `json:"acr_values"`            // OIDC Core §3.1.2.1
	UILocales            string          `json:"ui_locales"`            // OIDC Core §3.1.2.1
	Claims               json.RawMessage `json:"claims"`                // OIDC Core §5.5
	ClientAssertion      string          `json:"client_assertion"`      // RFC 7521 + 7523
	ClientAssertionType  string          `json:"client_assertion_type"` // RFC 7521 + 7523
}

// authenticatePARClient resolves and authenticates the PAR client,
// writing the wire response and returning ok=false on any failure. On
// success it returns the resolved *Client and mutates req.ClientID to
// the authoritative identity (e.g. the JWT assertion `sub`).
func authenticatePARClient(d PARDeps, ctx core.HandlerContext, req *parRequestForm) (*core.Client, bool) {
	clientStore := d.ClientStoreAccessor()

	if !resolvePARClientAssertion(d, ctx, req) {
		return nil, false
	}

	if req.ClientID == "" {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrMissingClientID))
		return nil, false
	}

	client, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return nil, false
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrInactiveClient))
		return nil, false
	}
	if !tenant.ClientOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrTenantMismatch))
		return nil, false
	}
	// Skip client_secret validation when the JWT assertion already
	// proved client identity (RFC 7521 §4.2 forbids requiring both).
	if req.ClientAssertion == "" {
		if err := clientStore.ValidateSecret(ctx.Request().Context(), req.ClientID, req.ClientSecret); err != nil {
			// RFC 6749 §5.2: client-auth failure is invalid_client (same code
			// as unknown-client above — oracle-safe, no client_id enumeration).
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return nil, false
		}
	}
	return client, true
}

// resolvePARClientAssertion handles RFC 7521/7523 JWT bearer client
// authentication. When an assertion is supplied, the JWT's `sub` claim
// is the authoritative client identity (form `client_id` MUST agree if
// supplied at all), so on success it overwrites req.ClientID. Returns
// false (after writing the wire response) on any assertion failure; a
// no-assertion request is a no-op returning true.
func resolvePARClientAssertion(d PARDeps, ctx core.HandlerContext, req *parRequestForm) bool {
	if req.ClientAssertion == "" && req.ClientAssertionType == "" {
		return true
	}
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	assertedID, err := d.VerifyJWTClientAssertion(
		ctx.Request().Context(),
		req.ClientAssertion,
		req.ClientID,
		d.ResolveIssuer(ctx),
	)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return false
	}
	req.ClientID = assertedID
	return true
}

// validatePARRequestParams runs the post-auth parameter gates in
// order. Each gate emits its OWN distinct wire code (length limits /
// redirect_uri / resource / response_mode / authorization_details) —
// they are NOT collapsed to a single error return. Returns false
// (after writing the response) on the first failing gate.
func validatePARRequestParams(ctx core.HandlerContext, req *parRequestForm, client *core.Client) bool {
	// Parameter length limits — prevent DoS via oversized params that
	// would bloat PAR store entries and amplify redirect responses.
	if code := CheckAuthParamLengths(
		req.State, req.RedirectURI, req.Scope, req.Nonce, req.Resource,
	); code != "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(code))
		return false
	}
	if req.RedirectURI != "" && !client.IsRedirectURIValid(req.RedirectURI) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRedirectURI))
		return false
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidTarget))
		return false
	}
	// OIDC Form Post 1.0: reject malformed response_mode at PAR time
	// so the caller fails fast (whole point of PAR — surface
	// validation upstream of the user-agent redirect).
	if req.ResponseMode != "" && !IsValidResponseMode(req.ResponseMode) {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	// RFC 9396: validate authorization_details up front so a
	// malformed / disallowed payload fails at PAR time rather than
	// surfacing later at /auth/login (PAR's whole point is to move
	// validation upstream of the user-agent redirect).
	if _, err := ValidateAuthorizationDetails(req.AuthorizationDetails, client.AllowedAuthorizationDetailsTypes); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBodyDesc(ErrInvalidAuthorizationDetails, err.Error()))
		return false
	}
	return true
}

// issuePARRequest stores the validated request and writes the 201
// request_uri response (or 500 on store failure).
func issuePARRequest(d PARDeps, ctx core.HandlerContext, req *parRequestForm) {
	ttl := d.PARTTL()
	if ttl <= 0 {
		ttl = DefaultPARTTL
	}
	uri, err := d.PARStore().Issue(ctx.Request().Context(), &PARRequest{
		ClientID:             req.ClientID,
		ResponseType:         req.ResponseType,
		RedirectURI:          req.RedirectURI,
		Scope:                SplitScope(req.Scope),
		State:                req.State,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resource:             req.Resource,
		AuthorizationDetails: CloneRawJSON(req.AuthorizationDetails),
		LoginHint:            req.LoginHint,
		ResponseMode:         req.ResponseMode,
		ACRValues:            req.ACRValues,
		UILocales:            req.UILocales,
		Claims:               CloneRawJSON(req.Claims),
		ExpiresAt:            time.Now().Add(ttl),
	})
	if err != nil {
		d.SrvLogger().Error("par issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	ctx.JSON(http.StatusCreated, map[string]any{
		"request_uri": uri,
		"expires_in":  int(ttl.Seconds()),
	})
}
