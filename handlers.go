package sso

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
)

// tracer is shared by audit-event helpers for parsing inbound W3C
// traceparent headers into TraceID/SpanID for stamping on Event
// records. Stateless — safe at package scope.
var tracer = audit.NewTracer()

// active state + standard metadata claims for a presented access or
// refresh token. Inactive tokens return {active: false} only, with no
// extra metadata — §2.2 mandates this to limit oracle leakage.
//
// Auth: the introspecting client authenticates with client_id +
// client_secret (Basic auth or form body). Per §2.1 any registered
// active client may introspect — production deployments that want
// stronger isolation should layer an authorization middleware that
// checks a custom "introspect" scope or role on the client.
// handleIntrospect delegates to oauth.HandleIntrospect — see that
// file for the RFC 7662 + 7521/7523 client-auth precedence + §2.2
// {active:false} oracle-leak hardening.
func (s *Server) handleIntrospect(ctx HandlerContext) { oauth.HandleIntrospect(s, ctx) }

// authenticateClientCreds verifies the client_id + secret pair via
// the wired ClientStore + tenant gate. Used by handleRevoke + future
// handle_par migration. Returns nil on success.
func (s *Server) authenticateClientCreds(ctx HandlerContext, id, secret string) error {
	if id == "" || secret == "" {
		return errors.New("missing client credentials")
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		return err
	}
	if !client.Active {
		return errors.New("inactive client")
	}
	if !clientTenantOK(ctx, client) {
		return errors.New("tenant mismatch")
	}
	return s.clientStore.ValidateSecret(ctx.Request().Context(), id, secret)
}

// basicClientCreds delegates to oauth.BasicClientCreds — see that
// function for the RFC 6749 §2.3.1 precedence rationale.
func basicClientCreds(r *http.Request) (id, secret string, ok bool) {
	return oauth.BasicClientCreds(r)
}

// handlePAR implements RFC 9126 Pushed Authorization Requests.
// Confidential clients POST their authorization request parameters
// here BEFORE redirecting the user agent, getting back an opaque
// request_uri they then pass to /auth/login. This pre-registration
// pattern:
//
//   - Authenticates the client BEFORE the user-agent redirect (the
//     traditional authorization flow has the AS see the client
//     only AFTER the redirect, when there's nothing to do about a
//     bad request beyond rendering an error).
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
//
// Spec sentinel mapping:
//   - missing client credentials              → 401 invalid_client
//   - PAR store not wired                     → 501 par_not_configured
//   - invalid redirect_uri allowlist          → 400 invalid_redirect_uri
//   - resource not in allowlist (RFC 8707)    → 400 invalid_target
//
// Response per RFC 9126 §2.2:
//
//	{
//	  "request_uri": "urn:ietf:params:oauth:request_uri:<token>",
//	  "expires_in":  90
//	}
// handlePAR delegates to oauth.HandlePAR — see that file for the
// RFC 9126 pre-redirect client authentication + validation flow.
func (s *Server) handlePAR(ctx HandlerContext) { oauth.HandlePAR(s, ctx) }

// handleRevoke implements RFC 7009 token revocation. Per-token
// revocation that's complementary to /logout (which is session-scoped).
//
// Auth: same client credentials as /token/introspect. Per §2 any
// registered active client may revoke — but the server MUST NOT
// distinguish revocation of an unknown token from a successful
// revocation (§2.2), so the wire response is always 200 OK with an
// empty body when the credentials are valid, regardless of whether
// the token existed.
//
// token_type_hint is honored as an optimization (try the named tier
// first) but the server still attempts the other tier on miss, so a
// wrong hint doesn't leave the token alive.
// handleRevoke delegates to oauth.HandleRevoke — see that file for
// the §2.2 always-200 oracle-leak hardening + hint-driven
// best-effort dual-tier revocation.
func (s *Server) handleRevoke(ctx HandlerContext) { oauth.HandleRevoke(s, ctx) }

// handleRevokeAll implements the "logout everywhere" endpoint. The
// user presents a bearer token; the server reads sub + aud from its
// claims, then kills every refresh token bound to that
// (subject, client) pair via the optional oauth.RefreshTokenSubjectIndex
// extension. The presented access token is also revoked via the
// normal per-issuer path so it stops working immediately.
//
// Useful for a "sign out of all devices" button — one round trip
// instead of per-device per-token revocation.
//
// Requires the oauth.RefreshTokenStore to implement
// oauth.RefreshTokenSubjectIndex; without it, the response is 501.
//
// Authentication: bearer token only (not client credentials). The
// user is the actor — they're authorizing the revocation of their
// own tokens.
// handleRevokeAll delegates to oauth.HandleRevokeAll — see that
// file for the bearer-token-authenticated "logout everywhere"
// semantics via the RefreshTokenSubjectIndex extension.
func (s *Server) handleRevokeAll(ctx HandlerContext) { oauth.HandleRevokeAll(s, ctx) }

// handleTokenExchangeGrant implements RFC 8693 OAuth 2.0 Token
// Exchange. The grant lets one party swap an existing token for
// another — typically a downstream service exchanging the user's
// access token for a token scoped specifically to its callee, so
// the original token isn't replayed across services (the "confused
// deputy" defense that resource indicators (RFC 8707) is also
// designed for).
//
// Request (form-encoded per RFC 6749 §3.2):
//
//   - grant_type            urn:ietf:params:oauth:grant-type:token-exchange
//   - subject_token         REQUIRED — the token being exchanged
//   - subject_token_type    REQUIRED — token type URI
//   - resource              RFC 8707 audience (zero or more)
//   - audience              RFC 8693 audience (zero or more)
//   - scope                 OPTIONAL — narrow the issued token's scope
//   - requested_token_type  OPTIONAL — defaults to access_token
//   - actor_token /
//     actor_token_type      OPTIONAL — for delegation chains
//
// Response per §2.2.1:
//
//	{
//	  "access_token":      "<new token>",
//	  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
//	  "token_type":        "Bearer",
//	  "expires_in":        N,
//	  "scope":             "...",
//	  "token_strategy":    "<wired strategy name>"
//	}
//
// v1 supports:
//   - Subject token type access_token (the common case — exchange a
//     bearer for a more narrowly-audienced bearer).
//   - Requested token type access_token (default) and refresh_token
//     (when WithRefreshTokenStore is wired — opts in the family
//     rotation + RFC 8693 §2.2 issued_token_type=refresh_token
//     response shape).
//   - resource + audience (merged into the new token's aud claim).
//   - Scope narrowing (subset of the subject token's scopes).
//   - actor_token replay protection via WithJTIReplayStore.
//
// Future-scope (deliberately deferred for v1):
//   - JWT / SAML subject tokens (requires bespoke validators).
//   - Actor token delegation chain in the issued token's claims.
//
// Sentinel mapping:
//
//   - missing subject_token / subject_token_type → 400 invalid_request
//   - unsupported subject_token_type → 400 invalid_request
//   - subject_token failed validation → 400 invalid_grant
//   - unregistered resource / audience → 400 invalid_target (RFC 8707)
//   - scope expansion attempt → 400 invalid_scope (RFC 6749 §6 analogue)
//   - unsupported requested_token_type → 400 invalid_request
func (s *Server) handleTokenExchangeGrant(ctx HandlerContext, client *Client, req tokenExchangeRequest) {
	if req.SubjectToken == "" || req.SubjectTokenType == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.SubjectTokenType != TokenTypeAccessToken &&
		req.SubjectTokenType != TokenTypeJWT {
		// RFC 8693 §2.1 lists more token types; v1 only handles
		// signed access tokens issued by this server.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.RequestedTokenType != "" &&
		req.RequestedTokenType != TokenTypeAccessToken &&
		req.RequestedTokenType != TokenTypeRefreshToken {
		// Access + Refresh supported; ID token / SAML2 are future
		// work (no compelling caller need yet). Anything else =>
		// caller wanted something we can't deliver.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// Refresh-token output requires a wired refresh store — without
	// it there's no way to honor the resulting rotation grant. Fail
	// fast rather than silently downgrade to access-only.
	if req.RequestedTokenType == TokenTypeRefreshToken && s.refreshTokenStore == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrRefreshTokenNotConfigured))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), req.SubjectToken)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// RFC 9470 step-up: when the caller demands a minimum ACR via
	// `acr_values`, the inbound subject_token's ACR claim MUST match
	// at least one value in the demand set. Otherwise the AS would
	// have to re-authenticate the user, which token-exchange
	// (server-to-server) can't do — caller must instead route the
	// user through /auth/login with the same acr_values. Same wire
	// shape as the resource-server challenge (insufficient_user_authentication)
	// so SPAs branch on it uniformly across grants.
	if req.ACRValues != "" {
		demanded := strings.Fields(req.ACRValues)
		if !acrMatchesAny(claims.ACR, demanded) {
			ctx.JSON(http.StatusBadRequest, errorBody(security.ErrInsufficientUserAuthentication))
			return
		}
	}

	// RFC 8693 §2.1: actor_token and actor_token_type MUST both
	// be present, or both absent. Mismatch = invalid_request.
	if (req.ActorToken == "") != (req.ActorTokenType == "") {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	var actor *ActorClaim
	if req.ActorToken != "" {
		if req.ActorTokenType != TokenTypeAccessToken && req.ActorTokenType != TokenTypeJWT {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
			return
		}
		actorClaims, _, aerr := s.validateAnyToken(ctx.Request().Context(), req.ActorToken)
		if aerr != nil || actorClaims == nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
		// Defense-in-depth: when a security.JTIReplayStore is wired AND the
		// actor_token carries a `jti`, refuse to honor the same
		// delegation assertion twice within its expiry window. The
		// actor_token is a short-lived delegation proof — replay
		// would let a captured proof be re-used to mint new
		// downstream tokens after the legitimate exchange already
		// happened. Mirrors the same defense JAR + DPoP +
		// client_assertion already opt into; namespace prevents
		// collision with those jti spaces. Empty jti / no store /
		// store error all fall through (RFC 8693 doesn't mandate
		// the check; collapse to invalid_grant on confirmed reuse).
		if s.jtiReplayStore != nil && actorClaims.JTI != "" {
			expiry := actorClaims.ExpiresAt
			if expiry.IsZero() {
				expiry = time.Now().Add(security.DefaultJTIReplayWindow)
			}
			first, rerr := s.jtiReplayStore.MarkSeen(ctx.Request().Context(), "tokex-act:"+actorClaims.JTI, expiry)
			if rerr == nil && !first {
				ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
				return
			}
		}
		// RFC 8693 §4.1.1: when the subject_token already carries
		// an `act` claim (it was itself a delegated token), the
		// new act prepends the current actor and nests the
		// previous chain beneath, preserving full provenance.
		// Reading outside-in walks the delegation chain in
		// time-order: outermost is most recent.
		actor = &ActorClaim{Subject: actorClaims.Subject, Actor: claims.Actor}
	}

	// Merge `resource` + `audience` into the new token's aud claim.
	// Both parameter forms are accepted (RFC 8693 + RFC 8707
	// overlap on intent); deduplicated in-order so the first
	// occurrence wins for deterministic output.
	resources := mergeTargets(req.Resource, req.Audience)
	if !client.AreResourcesAllowed(resources) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	// Scope narrowing per RFC 8693 §2.1: when `scope` is supplied
	// it MUST be a subset of the subject_token's scopes; expansion
	// is forbidden. Empty scope = keep the subject's scopes.
	scopes := claims.Scopes
	if req.Scope != "" {
		requested := strings.Split(req.Scope, " ")
		if !isScopeSubset(requested, claims.Scopes) {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
			return
		}
		scopes = requested
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}

	// Carry the subject identity through. The new token's `sub` is
	// the same as the subject_token's — token exchange does NOT
	// change the principal, only the audience / scope. ClientID is
	// the requesting (downstream) client, NOT the original; that's
	// the canonical RFC 8693 semantic ("on behalf of the same
	// subject, scoped to me").
	// OIDC §8 pairwise: the inbound subject_token's `sub` may be
	// pairwise (issued for the originating client's sector); resolve to
	// the local sub, then re-apply pairwise for the new (downstream)
	// client's sector. The exchange does not change the principal but
	// the wire sub differs whenever the downstream client lives in a
	// different sector. Non-pairwise deployments are a no-op pair.
	localSub, perr := s.resolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		s.logger.Error("pairwise resolve failed at token-exchange", "error", perr, "subject", claims.Subject)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, localSub)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:        issuedSub,
		Claims:    claims.Extra,
		Resources: resources,
		ClientID:  client.ID,
		// auth_time + amr propagate from the original subject_token
		// — the exchange doesn't represent a fresh end-user auth
		// event; carrying the originals lets downstream services
		// see the actual factor strength.
		AuthTime: claims.AuthTime,
		ACR:      claims.ACR,
		AMR:      append([]string(nil), claims.AMR...),
		// RFC 8693 §4.1 — when an actor_token is presented, the
		// new token carries `act: {sub: <actor.sub>}` so
		// downstream services can audit who acted on behalf of
		// whom. Nil when no actor_token was supplied (the direct
		// non-delegated path).
		Actor: actor,
		TTL:   client.AccessTokenTTL,
		// RFC 9396: preserve the subject_token's authorization_details
		// across the exchange so the resulting token carries the
		// same fine-grained authorization the user originally
		// consented to. The downstream service relying on RAR
		// shouldn't lose its binding just because a token was
		// exchanged into a narrower audience.
		AuthorizationDetails: oauth.CloneRawJSON(claims.AuthorizationDetails),
	}, scopes)
	if err != nil {
		s.logger.Error("token exchange issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordTokenIssued(ctx, client.ID, strategy, claims.Subject)
	s.recordSubjectClientAccess(ctx.Request().Context(), claims.Subject, client.ID)

	resp := map[string]any{
		KeyAccessToken:     token.AccessToken,
		KeyIssuedTokenType: TokenTypeAccessToken,
		KeyTokenType:       token.TokenType,
		KeyExpiresIn:       token.ExpiresIn,
		KeyScope:           token.Scope,
		KeyTokenStrategy:   strategy,
	}
	// RFC 8693 §2.1: when requested_token_type is refresh_token,
	// mint a refresh token alongside (the access token is always
	// returned — the spec uses requested_token_type to name what
	// the `issued_token_type` field reports back, not what's
	// emitted exclusively). Provider/AMR/Resources/AuthDetails/SID
	// propagate from the subject_token's claims so a rotated
	// chain inherits the same authorization context.
	if req.RequestedTokenType == TokenTypeRefreshToken && s.refreshTokenStore != nil {
		provider := ""
		if len(claims.AMR) > 0 {
			provider = claims.AMR[0]
		}
		rt, rerr := s.issueRefreshToken(
			ctx.Request().Context(),
			claims.Subject, client.ID, provider,
			scopes, claims.Extra, "", resources,
			oauth.CloneRawJSON(claims.AuthorizationDetails), // RFC 9396 — propagate the inbound binding
			claims.SID,
			client.RefreshTokenTTL,
		)
		if rerr != nil {
			s.logger.Error("token exchange refresh issue failed", "strategy", strategy, "error", rerr)
			// Fail-open: caller still gets the access token. Spec
			// allows this since the access token alone is a complete
			// response; the refresh is a bonus capability the caller
			// can re-request.
		} else {
			resp[KeyRefreshToken] = rt
			resp[KeyIssuedTokenType] = TokenTypeRefreshToken
			s.recordRefreshTokenIssued(ctx, client.ID, claims.Subject, false)
		}
	}

	ctx.JSON(http.StatusOK, resp)
}

// tokenExchangeRequest is the subset of /token parameters the
// token-exchange grant cares about. Pulled out of the main /token
// request struct so the switch branch reads cleanly.
type tokenExchangeRequest struct {
	SubjectToken       string
	SubjectTokenType   string
	ActorToken         string
	ActorTokenType     string
	Resource           []string
	Audience           []string
	Scope              string
	RequestedTokenType string
	// RFC 9470 step-up: caller-asserted ACR floor for the exchanged
	// token. Space-separated values; the inbound subject_token's
	// ACR claim MUST be a member of this set or the exchange fails
	// with insufficient_user_authentication. Empty = no demand
	// (inbound ACR transparently propagates as today).
	ACRValues string
}

// acrMatchesAny + mergeTargets delegate to oauth/token_exchange_helpers.go.
func acrMatchesAny(inbound string, demanded []string) bool {
	return oauth.ACRMatchesAny(inbound, demanded)
}

func mergeTargets(primary, secondary []string) []string {
	return oauth.MergeTargets(primary, secondary)
}

// handleEndSession implements OpenID Connect RP-Initiated Logout 1.0.
// Unlike POST /logout (a session-scoped bearer-authenticated kill
// switch), this is a GET endpoint a relying party can redirect the
// user agent to so the SSO server logs the user out and then sends
// them back to the RP's post-logout page.
//
// Query parameters (per the spec §2):
//
//   - id_token_hint            REQUIRED to identify the user — a
//     previously-issued id_token. The server
//     validates the signature and uses the
//     token's aud claim to look up the client.
//   - post_logout_redirect_uri Optional; MUST be in the client's
//     PostLogoutRedirectURIs allowlist.
//   - state                    Optional; echoed back on the redirect.
//   - client_id                Optional fallback when id_token_hint
//     is absent — used only for
//     redirect-uri allowlist lookup, NOT
//     for session termination.
//
// Behavior:
//
//   - Always best-effort revokes the access token derived from the
//     id_token_hint (so a stolen id_token_hint can't be used to
//     just bounce the user without invalidating their session).
//   - When post_logout_redirect_uri is in the allowlist, returns
//     302 with Location pointing at the redirect_uri (+ state when
//     supplied).
//   - When the redirect_uri is missing or rejected, returns 204 —
//     the session is dead, but we don't open a redirect-vector for
//     callers without a registered URL.
//
// Security:
//
//   - id_token_hint signature MUST verify against the server's
//     wired token issuers (we treat ID tokens and access tokens
//     as signed by the same key pair).
//   - post_logout_redirect_uri MUST exact-match (no path tolerance,
//     no scheme-only match) — phishing defense per §3.
// handleEndSession delegates to oidc.HandleEndSession — see that
// file for the OIDC RP-Initiated Logout 1.0 flow, including FCL
// iframe gather/render + BCL fan-out + phishing-safe redirect
// allowlist semantics.
func (s *Server) handleEndSession(ctx HandlerContext) { oidc.HandleEndSession(s, ctx) }

// dcrRequest mirrors the RFC 7591 §2 client metadata subset this
// server understands. Unknown fields are ignored per §3.1 ("the
// authorization server MUST ignore values it does not understand").
type dcrRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
	Contacts                []string `json:"contacts"`
	TokenStrategy           string   `json:"token_strategy"`
	AllowedAuthenticators   []string `json:"allowed_authenticators"`
	AllowedResources        []string `json:"allowed_resources"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	TenantID                string   `json:"tenant_id"`
	RequirePKCE             bool     `json:"require_pkce"`
}

// dcrResponse is the RFC 7591 §3.2.1 successful-registration body.
// Echoes every accepted metadata field plus the issued credentials,
// timestamps, and the RFC 7592 management URI / access token when
// the management endpoint is enabled.
type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TokenStrategy           string   `json:"token_strategy,omitempty"`
	AllowedAuthenticators   []string `json:"allowed_authenticators,omitempty"`
	AllowedResources        []string `json:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	RequirePKCE             bool     `json:"require_pkce,omitempty"`
}

// handleRegister implements RFC 7591 Dynamic Client Registration.
// Opt-in via WithDynamicClientRegistration; without it /register
// returns 501.
//
// Auth gate: requires the configured initial access token (a
// pre-shared bearer the operator distributes) unless the policy's
// AllowOpenRegistration=true is set. Open registration is
// supported but discouraged — every public registration endpoint
// in the wild eventually gets used for resource exhaustion.
//
// Response per §3.2.1: 201 Created + the issued credentials +
// the echoed metadata. Public clients (token_endpoint_auth_method
// = "none") skip secret generation per §2.
func (s *Server) handleRegister(ctx HandlerContext) {
	// DCR responses ship client_secret + registration_access_token —
	// credential-shaped bodies that intermediaries must not cache.
	// Same RFC 6749 §5.1 pattern as /token.
	tokenNoStoreHeaders(ctx)
	if s.dcrPolicy == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(oauth.ErrRegistrationDisabled))
		return
	}
	if err := s.requireDeps(DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	// Authentication gate. Initial-access-token takes precedence
	// when configured; AllowOpenRegistration is the explicit
	// escape hatch.
	if !s.dcrPolicy.AllowOpenRegistration {
		if s.dcrPolicy.InitialAccessToken == "" {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
			return
		}
		if bearer := bearerToken(ctx.Request()); bearer != s.dcrPolicy.InitialAccessToken {
			setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Initial access token missing or invalid")
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
			return
		}
	}

	var req dcrRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}

	if err := validateDCRMetadata(&req, s.dcrPolicy); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}

	id, err := oauth.GenerateClientID()
	if err != nil {
		s.logger.Error("dcr id gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// Public clients (no secret) per RFC 7591 §2 +
	// RFC 6749 §2.3 — the "none" auth method opts out of secret
	// issuance entirely. SPAs and mobile apps that hold no
	// confidential secret should request this.
	public := req.TokenEndpointAuthMethod == "none"
	secret := ""
	if !public {
		secret, err = oauth.GenerateClientSecret()
		if err != nil {
			s.logger.Error("dcr secret gen failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
	}

	// RFC 7592 §3: every newly-registered client gets a
	// registration_access_token so the client itself can later
	// GET/PUT/DELETE its own registration without operator
	// involvement. The token is bearer-shaped; deployments
	// storing clients on disk SHOULD hash it at rest.
	regToken, err := oauth.GenerateClientSecret()
	if err != nil {
		s.logger.Error("dcr reg-token gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = s.dcrPolicy.DefaultTokenStrategy
	}

	client := &Client{
		ID:                      id,
		Secret:                  secret,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           splitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		Active:                  s.dcrPolicy.DefaultActive,
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || public, // public clients always PKCE
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
		RegistrationAccessToken: regToken,
	}

	if err := s.clientStore.Add(ctx.Request().Context(), client); err != nil {
		s.logger.Error("dcr persist failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	now := time.Now().Unix()
	resp := dcrResponse{
		ClientID:                id,
		ClientSecret:            secret,
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:   0, // 0 = never expires per RFC 7591 §3.2.1
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   requestBaseURL(ctx.Request()) + oauth.PathRegister + "/" + id,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              client.Name,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TokenStrategy:           client.TokenStrategy,
		AllowedAuthenticators:   client.AllowedAuthenticators,
		AllowedResources:        client.AllowedResources,
		PostLogoutRedirectURIs:  client.PostLogoutRedirectURIs,
		RequirePKCE:             client.RequirePKCE,
	}

	ctx.JSON(http.StatusCreated, resp)
}

// handleRegistrationGet implements RFC 7592 §2.1 — the client
// itself reads its current registration metadata. Auth: bearer
// matching the registration_access_token issued at /register.
func (s *Server) handleRegistrationGet(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	client, ok := s.authorizeRegistrationMgmt(ctx)
	if !ok {
		return
	}
	ctx.JSON(http.StatusOK, projectClientToDCRResponse(client, ctx))
}

// handleRegistrationPut implements RFC 7592 §2.2 — the client
// itself updates its metadata. Auth: bearer matching the
// registration_access_token. Validation: same rules as POST
// /register; the client_secret stays unchanged across updates
// (rotation is a separate admin RPC). The registration_access_token
// is also preserved so the caller can keep managing the registration.
func (s *Server) handleRegistrationPut(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	client, ok := s.authorizeRegistrationMgmt(ctx)
	if !ok {
		return
	}

	var req dcrRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}
	if err := validateDCRMetadata(&req, s.dcrPolicy); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(oauth.ErrInvalidClientMetadata, err.Error()))
		return
	}

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = client.TokenStrategy
	}

	updated := &Client{
		ID:                      client.ID,
		Secret:                  client.Secret,                  // unchanged
		RegistrationAccessToken: client.RegistrationAccessToken, // unchanged
		Active:                  client.Active,
		Name:                    req.ClientName,
		RedirectURIs:            append([]string(nil), req.RedirectURIs...),
		AllowedScopes:           splitScope(req.Scope),
		AllowedAuthenticators:   append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:           tokenStrategy,
		TenantID:                req.TenantID,
		RequirePKCE:             req.RequirePKCE || req.TokenEndpointAuthMethod == "none",
		AllowedResources:        append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs:  append([]string(nil), req.PostLogoutRedirectURIs...),
	}

	if err := s.clientStore.Update(ctx.Request().Context(), updated); err != nil {
		s.logger.Error("dcr update failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, projectClientToDCRResponse(updated, ctx))
}

// handleRegistrationDelete implements RFC 7592 §2.3 — the client
// itself removes its registration. Auth: bearer matching the
// registration_access_token. Successful response: 204 No Content
// per §2.3.
func (s *Server) handleRegistrationDelete(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	client, ok := s.authorizeRegistrationMgmt(ctx)
	if !ok {
		return
	}
	if err := s.clientStore.Delete(ctx.Request().Context(), client.ID); err != nil {
		s.logger.Error("dcr delete failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.ResponseWriter().WriteHeader(http.StatusNoContent)
}

// authorizeRegistrationMgmt is the shared auth + lookup gate for
// every RFC 7592 endpoint. Resolves the client by path param,
// constant-time compares the presented bearer against the stored
// registration_access_token, and writes the appropriate error
// response when checks fail.
//
// Returns (client, true) on success; on failure it has already
// written the response and returns (nil, false).
func (s *Server) authorizeRegistrationMgmt(ctx HandlerContext) (*Client, bool) {
	if s.dcrPolicy == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(oauth.ErrRegistrationDisabled))
		return nil, false
	}
	if err := s.requireDeps(DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return nil, false
	}
	id := ctx.Param("client_id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return nil, false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		// 401 (not 404) because the resource is auth-gated; a 404
		// would let an unauthed caller probe for client_id existence.
		// The challenge stays identical across "unknown client",
		// "missing bearer", and "wrong bearer" to preserve the
		// anti-enumeration property the catch-all 401 enforces.
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	bearer := bearerToken(ctx.Request())
	if bearer == "" || client.RegistrationAccessToken == "" {
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	if subtleConstantTimeStringEq(bearer, client.RegistrationAccessToken) != 1 {
		setBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "Registration access token missing or invalid")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	return client, true
}

// projectClientToDCRResponse builds an RFC 7591-shaped response from
// a stored Client. Re-used by GET/PUT — the registration_access_token
// is NOT re-emitted (RFC 7592 §2.1: server SHOULD NOT include it on
// reads; the original /register response is the only canonical
// distribution point).
func projectClientToDCRResponse(c *Client, ctx HandlerContext) dcrResponse {
	return dcrResponse{
		ClientID:               c.ID,
		ClientSecret:           c.Secret, // RFC 7592 §2.1 SHOULD include
		ClientSecretExpiresAt:  0,
		RegistrationClientURI:  requestBaseURL(ctx.Request()) + oauth.PathRegister + "/" + c.ID,
		RedirectURIs:           c.RedirectURIs,
		ClientName:             c.Name,
		Scope:                  joinScope(c.AllowedScopes),
		TokenStrategy:          c.TokenStrategy,
		AllowedAuthenticators:  c.AllowedAuthenticators,
		AllowedResources:       c.AllowedResources,
		PostLogoutRedirectURIs: c.PostLogoutRedirectURIs,
		RequirePKCE:            c.RequirePKCE,
	}
}

func joinScope(scopes []string) string { return oauth.JoinScope(scopes) }

// subtleConstantTimeStringEq delegates to security.ConstantTimeStringEq.
func subtleConstantTimeStringEq(a, b string) int { return security.ConstantTimeStringEq(a, b) }

// validateDCRMetadata adapts the root dcrRequest to oauth.DCRMetadata
// and delegates to oauth.ValidateDCRMetadata.
func validateDCRMetadata(req *dcrRequest, policy *oauth.DCRPolicy) error {
	return oauth.ValidateDCRMetadata(&oauth.DCRMetadata{
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		AllowedAuthenticators:   req.AllowedAuthenticators,
	}, policy, SupportedGrants, GrantAuthorizationCode)
}

// mfaResumeState is the JSON-encoded blob persisted alongside the
// spi.MFAChallenge. Opaque to spi.MFAChallengeStore backends; the SSO server
// marshals + unmarshals so the post-step-up handler can replay the
// same finishLogin flow the no-MFA path takes.
type mfaResumeState struct {
	Result  *AuthResult  `json:"result"`
	Request loginRequest `json:"request"`
}

// issueMFAChallenge mints a single-use challenge ID + persists the
// frozen login state for resumption. Writes the mfa_required response.
// Audit: emits mfa_required (success outcome — primary credential was
// fine, the user just hasn't completed step-up yet).
func (s *Server) issueMFAChallenge(ctx HandlerContext, result *AuthResult, req loginRequest, client *Client) {
	stateBlob, err := json.Marshal(&mfaResumeState{Result: result, Request: req})
	if err != nil {
		s.logger.Error("mfa: failed to marshal resume state", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	id, err := newMFAChallengeID()
	if err != nil {
		s.logger.Error("mfa: failed to mint challenge id", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	ttl := s.mfaChallengeTTL
	if ttl <= 0 {
		ttl = spi.DefaultMFAChallengeTTL
	}
	now := time.Now()
	challenge := &spi.MFAChallenge{
		ID:           id,
		SubjectID:    result.UserID,
		ClientID:     client.ID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		RequestState: stateBlob,
	}
	if err := s.mfaChallengeStore.Put(ctx.Request().Context(), challenge); err != nil {
		s.logger.Error("mfa: failed to persist challenge", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	if s.auditor != nil {
		evt := &audit.Event{
			Type:     audit.EventMFARequired,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  result.UserID,
			ClientID: client.ID,
			Provider: result.Provider,
			ActorIP:  audit.ClientIP(ctx.Request()),
		}
		audit.SetMeta(evt, KeyMFAChallengeID, id)
		s.auditor.Record(ctx.Request().Context(), evt)
	}

	methods := s.mfaProvider.SupportedMethods()
	// Metric: count one challenge per issuance, labeled by the FIRST
	// supported method (the user picks among them downstream). Zero
	// traffic when metrics aren't wired.
	if s.metrics != nil && len(methods) > 0 {
		s.metrics.MFAChallengesTotal.WithLabelValues(methods[0]).Inc()
	}
	resp := map[string]any{
		KeyError:          ErrMFARequired, // top-level error field so SPAs treating non-2xx-but-pending uniformly still surface it
		KeyMFAChallengeID: id,
		KeyMFAMethods:     methods,
		KeyIss:            s.resolveIssuer(ctx),
	}

	// spi.MFABeginner dispatch: providers needing server-side state
	// (WebAuthn challenge issuance, push notification fan-out, …)
	// get one Begin call per supported method. Results are bucketed
	// per method so clients picking method X read only their slice.
	// Per-method failure is non-fatal — the method stays in
	// mfa_methods but without an attached method_data entry; the
	// client can retry out-of-band or pick a different factor.
	if beginner, ok := s.mfaProvider.(spi.MFABeginner); ok && len(methods) > 0 {
		methodData := make(map[string]map[string]string, len(methods))
		for _, method := range methods {
			data, berr := beginner.Begin(ctx.Request().Context(), result.UserID, method)
			if berr != nil {
				s.logger.Error("mfa: begin failed", "method", method, "user", result.UserID, "error", berr)
				continue
			}
			if len(data) > 0 {
				methodData[method] = data
			}
		}
		if len(methodData) > 0 {
			resp[KeyMFAMethodData] = methodData
		}
	}

	if req.State != "" {
		resp[KeyState] = req.State
	}
	// HTTP 200 (not 400) — the primary credential was accepted; the
	// pending state is a normal step in the flow, not an error.
	ctx.JSON(http.StatusOK, resp)
}

// handleMFAComplete is the POST /auth/mfa endpoint. The client presents
// the challenge ID + factor name + method-specific params; on success
// the server replays finishLogin against the frozen state so the
// response shape matches what the no-MFA path would have returned.
//
// Oracle-leak hardening: every failure path (missing challenge,
// expired, wrong method, wrong factor) collapses to the same
// HTTP 400 + error=mfa_invalid response so probes can't distinguish
// the cases.
func (s *Server) handleMFAComplete(ctx HandlerContext) {
	// Observe /auth/mfa duration with outcome label. defer + named
	// outcome lets every return path (auth-invalid, factor-failed,
	// success, transport-error) account uniformly. The Push factor's
	// long polling loop dominates this histogram — operators
	// alerting on push-flow stalls graph p95 here.
	start := time.Now()
	outcome := "failure"
	defer func() {
		if s.metrics != nil {
			s.metrics.MFACompletionDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
		}
	}()

	tokenNoStoreHeaders(ctx)
	if s.mfaProvider == nil || s.mfaChallengeStore == nil {
		// Endpoint is registered unconditionally so discovery doesn't
		// have to be re-derived per request, but without a wired
		// provider it can't do useful work. 404 (not 501) so a probe
		// can't fingerprint the deployment as MFA-capable-but-misconfigured.
		ctx.JSON(http.StatusNotFound, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	// Mark outcome on the one success path; left as "failure" for
	// every other return point.
	_ = outcome

	var req struct {
		ChallengeID string            `json:"mfa_challenge_id"`
		Method      string            `json:"mfa_method"`
		Params      map[string]string `json:"params"`
		// Top-level convenience fields the flat-form callers prefer
		// (HTML forms, simple clients). When Params is empty we
		// collect the per-method known fields from these.
		Code      string `json:"code"`      // totp
		Assertion string `json:"assertion"` // webauthn
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	if req.ChallengeID == "" || req.Method == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}

	challenge, err := s.mfaChallengeStore.Consume(ctx.Request().Context(), req.ChallengeID)
	if err != nil || challenge == nil {
		s.recordMFAFailure(ctx, "", req.ChallengeID, req.Method, "challenge_invalid")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}

	// Flat → Params normalization. Params wins when both set so explicit
	// callers stay in control. The dispatch into spi.MFAProvider is opaque
	// — only the contract for "totp" / "webauthn" is known here; richer
	// providers (push notification, hardware key) get whatever Params
	// the caller supplies plus the flat code/assertion convenience.
	params := req.Params
	if params == nil {
		params = make(map[string]string, 2)
	}
	if _, ok := params["code"]; !ok && req.Code != "" {
		params["code"] = req.Code
	}
	if _, ok := params["assertion"]; !ok && req.Assertion != "" {
		params["assertion"] = req.Assertion
	}

	if err := s.mfaProvider.Verify(ctx.Request().Context(), challenge.SubjectID, req.Method, params); err != nil {
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, err.Error())
		s.recordMFACompletion(req.Method, "failure")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	s.recordMFACompletion(req.Method, "success")
	outcome = "success"

	// Factor verified. Decode the frozen state, re-look-up the client
	// (could have been deactivated / tenant-suspended in the window
	// between challenge issue and verify), and resume finishLogin.
	state := &mfaResumeState{}
	if err := json.Unmarshal(challenge.RequestState, state); err != nil {
		s.logger.Error("mfa: failed to decode resume state", "error", err, "challenge", req.ChallengeID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	if state.Result == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}

	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), challenge.ClientID)
	if err != nil || client == nil || !client.Active || !clientTenantOK(ctx, client) {
		// Client was deactivated, deleted, or tenant-suspended between
		// challenge issue and completion. Surface as inactive_client
		// rather than mfa_invalid — operators investigating the audit
		// trail need to know it wasn't the factor that failed.
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, "client_unavailable")
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}

	if s.auditor != nil {
		evt := &audit.Event{
			Type:     audit.EventMFASuccess,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  challenge.SubjectID,
			ClientID: client.ID,
			Provider: state.Result.Provider,
			ActorIP:  audit.ClientIP(ctx.Request()),
		}
		audit.SetMeta(evt, KeyMFAMethod, req.Method)
		audit.SetMeta(evt, KeyMFAChallengeID, req.ChallengeID)
		s.auditor.Record(ctx.Request().Context(), evt)
	}

	// Resume the standard post-risk login flow. finishLogin writes
	// the response, which can be the normal token/code/form-post
	// payload — caller can't tell the difference between an MFA-gated
	// login and a non-gated one (other than the extra round trip).
	s.finishLogin(ctx, state.Result, state.Request, client)
}

// recordMFACompletion increments the MFA completion metric for the
// (method, outcome) pair, but only when the metric is wired AND the
// method appears in the configured provider's SupportedMethods set.
// Restricting to known methods bounds metric cardinality — a
// user-controlled method field would otherwise let attackers spray
// arbitrary labels into Prometheus storage.
func (s *Server) recordMFACompletion(method, outcome string) {
	if s.metrics == nil || s.mfaProvider == nil {
		return
	}
	if slices.Contains(s.mfaProvider.SupportedMethods(), method) {
		s.metrics.MFACompletionsTotal.WithLabelValues(method, outcome).Inc()
	}
}

// recordMFAFailure emits the mfa_failure audit event with the
// operator-visible reason. The wire response is always mfa_invalid;
// reason here is for SIEM investigation, never returned to the client.
func (s *Server) recordMFAFailure(ctx HandlerContext, subjectID, challengeID, method, reason string) {
	audit.RecordMFAFailure(s.auditor, ctx, subjectID, challengeID, method, reason)
}

// newMFAChallengeID mints a 32-byte crypto/rand identifier encoded as
// URL-safe base64 without padding (so it survives query params /
// path segments / form bodies unchanged). 256 bits of entropy — same
// strength as oauth.AuthCodeStore / oauth.DeviceCodeStore identifiers.
func newMFAChallengeID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mfa: rand.Read: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// generateDeviceCodeBytes delegates to oauth.GenerateDeviceCode.
func generateDeviceCodeBytes() (string, error) { return oauth.GenerateDeviceCode() }

// generateUserCodeBytes delegates to oauth.GenerateUserCode.
func generateUserCodeBytes() (string, error) { return oauth.GenerateUserCode() }

// handleDeviceCode is the device-initiated endpoint of RFC 8628.
// The device POSTs its client_id (+ optional scope), the server
// returns device_code + user_code + verification_uri + interval +
// expires_in. The device then displays user_code + verification_uri
// to the user and starts polling /token.
func (s *Server) handleDeviceCode(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		ClientID string   `json:"client_id"`
		Scope    string   `json:"scope"`
		Nonce    string   `json:"nonce"`
		Resource []string `json:"resource"` // RFC 8707 resource indicators
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, errorBody(ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	deviceCode, err := generateDeviceCodeBytes()
	if err != nil {
		s.logger.Error("device code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	userCode, err := generateUserCodeBytes()
	if err != nil {
		s.logger.Error("user code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// TTL resolution precedence: per-client > server-wide > default.
	// Same shape as Client.RefreshTokenTTL / Client.AccessTokenTTL.
	ttl := client.DeviceCodeTTL
	if ttl <= 0 {
		ttl = s.deviceCodeTTL
	}
	if ttl <= 0 {
		ttl = DefaultDeviceCodeTTL
	}
	interval := client.DeviceCodePollInterval
	if interval <= 0 {
		interval = s.deviceCodeInterval
	}
	if interval <= 0 {
		interval = DefaultDevicePollMin
	}
	scopes := splitScope(req.Scope)

	// Store the normalized (dashless, uppercase) form as the lookup
	// key so /device/verify accepts the user_code with OR without the
	// cosmetic dash. The dashed form goes back to the device for
	// display only.
	dc := &oauth.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   normalizeUserCode(userCode),
		ClientID:   client.ID,
		Scopes:     scopes,
		Nonce:      req.Nonce,
		Interval:   interval,
		Resources:  append([]string(nil), req.Resource...),
		ExpiresAt:  time.Now().Add(ttl),
	}
	if err := s.deviceCodeStore.Issue(ctx.Request().Context(), dc); err != nil {
		s.logger.Error("device code issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordDeviceCodeIssued(ctx, client.ID)

	base := s.deviceVerifyBaseURL
	if base == "" {
		base = requestBaseURL(ctx.Request()) + PathDeviceVerify
	}
	complete := base
	if strings.Contains(complete, "?") {
		complete += "&user_code=" + userCode
	} else {
		complete += "?user_code=" + userCode
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base,
		"verification_uri_complete": complete,
		"expires_in":                int(ttl.Seconds()),
		"interval":                  int(interval.Seconds()),
	})
}

// handleDeviceVerify is the user-facing approval endpoint. The user
// has already authenticated separately (via /auth/login → bearer
// token, or any other path); they present the bearer here along
// with the user_code they read from the device + an approve/deny
// flag. The server validates both and updates the device code's
// state so the next device poll succeeds (or returns access_denied).
func (s *Server) handleDeviceVerify(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	bearer := bearerToken(ctx.Request())
	if bearer == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	var req struct {
		UserCode string `json:"user_code"`
		Approve  bool   `json:"approve"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	userCode := normalizeUserCode(req.UserCode)
	if userCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// All user_code lookups go through the normalized form so
	// dashed / dashless / mixed-case inputs all resolve to the same
	// entry (typo tolerance on a code the user typed by hand).
	dc, err := s.deviceCodeStore.GetByUserCode(ctx.Request().Context(), userCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	provider := ""
	if attrProvider, ok := claims.Extra["provider"]; ok {
		provider = attrProvider
	}

	// dc.UserCode is already the normalized form (we store dashless);
	// approval/denial routes back through the same key.
	if req.Approve {
		if err := s.deviceCodeStore.Approve(ctx.Request().Context(),
			dc.UserCode, claims.Subject, provider, claims.Extra); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	} else {
		if err := s.deviceCodeStore.Deny(ctx.Request().Context(), dc.UserCode); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	}
	s.recordDeviceCodeDecision(ctx, claims.Subject, dc.ClientID, req.Approve)

	ctx.JSON(http.StatusOK, map[string]any{KeyStatus: StatusOK})
}

// handleDeviceTokenGrant is the device's poll path on /token. Called
// from the GrantDeviceCode case in handleToken; pulled out so the
// switch stays readable.
//
// Returns one of the RFC 8628 §3.5 sentinels:
//   - authorization_pending: user hasn't acted yet
//   - slow_down: device polled faster than Interval (RFC says +5s)
//   - access_denied: user explicitly denied
//   - expired_token: TTL elapsed
//   - invalid_grant: unknown code / wrong client
//
// or a standard token response on success.
func (s *Server) handleDeviceTokenGrant(ctx HandlerContext, client *Client, deviceCode string) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	dc, err := s.deviceCodeStore.GetByDeviceCode(ctx.Request().Context(), deviceCode)
	if err != nil {
		if errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrExpiredToken))
			return
		}
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	// Bind: a device_code issued for client A can't be polled by client B.
	if dc.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// slow_down: poll arrived within Interval of the previous poll.
	now := time.Now()
	if !dc.LastPoll.IsZero() && now.Sub(dc.LastPoll) < dc.Interval {
		_ = s.deviceCodeStore.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSlowDown))
		return
	}
	_ = s.deviceCodeStore.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)

	if dc.Denied {
		_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAccessDenied))
		return
	}
	if !dc.Approved {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAuthorizationPending))
		return
	}

	// Approved → mint tokens, then delete the device code (single-use).
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, dc.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID: issuedSub, Provider: dc.Provider, Claims: dc.Attributes,
		Resources: dc.Resources,
		ClientID:  client.ID,
		AuthTime:  time.Now(),
		AMR:       []string{dc.Provider},
		TTL:       client.AccessTokenTTL,
	}, dc.Scopes)
	if err != nil {
		s.logger.Error("device token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	resp := map[string]any{
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
	}
	if s.refreshTokenStore != nil {
		// Device grant doesn't accept authorization_details today; pass
		// nil so refresh rotations don't fabricate a binding the user
		// never consented to.
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			dc.UserID, client.ID, dc.Provider, dc.Scopes, dc.Attributes, "", dc.Resources, nil, "", client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, dc.UserID, false)
		}
	}
	if slices.Contains(dc.Scopes, ScopeOpenID) && s.idTokenIssuer != nil {
		idToken, err := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
			Subject:  issuedSub,
			Audience: client.ID,
			Nonce:    dc.Nonce,
			AuthTime: time.Now(),
			AMR:      []string{dc.Provider},
			Claims:   dc.Attributes,
		})
		if err != nil {
			s.logger.Error("id token issue failed", "error", err)
		} else {
			resp[KeyIDToken] = idToken
			s.recordIDTokenIssued(ctx, client.ID, dc.UserID)
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	s.recordSubjectClientAccess(ctx.Request().Context(), dc.UserID, client.ID)
	_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
	ctx.JSON(http.StatusOK, resp)
}

// normalizeUserCode delegates to oauth.NormalizeUserCode.
func normalizeUserCode(s string) string { return oauth.NormalizeUserCode(s) }

// splitScope delegates to oauth.SplitScope.
func splitScope(s string) []string { return oauth.SplitScope(s) }

// Query parameter accepted by the /permissions/me, /menus/me, /roles/me
// endpoints to scope the lookup to a particular APP.
const QueryClientID = "client_id"

// authenticatedSubject resolves the bearer token to a user ID + client ID.
// client_id resolution: explicit query param > token audience > "".
func (s *Server) authenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return "", "", false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return "", "", false
	}
	clientID = ctx.Query(QueryClientID)
	if clientID == "" && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	return claims.Subject, clientID, true
}

// Netpolicy endpoint handlers moved to netpolicy/handlers.go. Methods
// below stay as thin delegators so the existing route binding via
// method values keeps working.

func (s *Server) handleListNetPolicies(ctx HandlerContext)    { netpolicy.HandleList(s, ctx) }
func (s *Server) handleGetNetPolicy(ctx HandlerContext)       { netpolicy.HandleGet(s, ctx) }
func (s *Server) handleApplyNetPolicy(ctx HandlerContext)     { netpolicy.HandleApply(s, ctx) }
func (s *Server) handleDeleteNetPolicy(ctx HandlerContext)    { netpolicy.HandleDelete(s, ctx) }
func (s *Server) handleClassifyNetPolicy(ctx HandlerContext)  { netpolicy.HandleClassify(s, ctx) }
func (s *Server) handleResolveMeNetPolicy(ctx HandlerContext) { netpolicy.HandleResolveMe(s, ctx) }

// ClassifyRequest is exposed for embedders that want to classify a request
// in their own middleware. Returns nil when no classifier is wired or no
// policy matches.
func (s *Server) ClassifyRequest(r *http.Request) *netpolicy.Policy {
	if s.netClassifier == nil || r == nil {
		return nil
	}
	return s.netClassifier.Classify(r.RemoteAddr, r.Host)
}

// audit.EventFromRequest pre-fills an Event with caller-side
// metadata (IP, user-agent, request ID, trace context, plus geo
// when the geo middleware is wired). Handlers fill the rest.
// TracingMiddleware populates the headers this function reads;
// without that middleware installed, RequestID/TraceID/SpanID
// stay empty. GeoMiddleware similarly populates the geo metadata
// keys; without it, no geo.* metadata appears.

// audit.EnrichTenant lifts tenant routing results onto
// Event.Metadata under the tenant.* prefix. No-op when the
// tenant middleware didn't run (no store wired, unknown host,
// suspended tenant). Tenant goes onto every audit event so
// SIEM filters like "show me failed logins for tenant X" become
// a single Metadata key check.

// audit.EnrichGeo lifts geo lookup results from HandlerContext onto
// Event.Metadata under the geo.* prefix. No-op when the geo
// middleware didn't run (no Lookup, ErrNotFound, nil Provider).
// Only non-empty fields are projected so audit consumers can do a
// presence check rather than a value check.

// audit.SetMeta writes key=val into e.Metadata, lazily allocating the map
// and skipping empty values. Use this instead of `e.Metadata = map[...]{...}`
// — direct assignment would clobber whatever audit.EventFromRequest
// already populated (geo enrichment, future fields).

// ctxKeyLoginStart is the HandlerContext.Set/Get key holding the
// time.Time stamped at /auth/login entry. Used by recordLogin* to
// observe the per-provider login duration histogram.
const ctxKeyLoginStart = "_sso_login_start"

// observeLoginDuration computes elapsed since the stamp + observes
// the histogram. Safe no-op when metrics aren't wired or the stamp
// is absent (defensive — tests may bypass handleLogin).
func (s *Server) observeLoginDuration(ctx HandlerContext, provider, outcome string) {
	if s.metrics == nil {
		return
	}
	v := ctx.Get(ctxKeyLoginStart)
	start, ok := v.(time.Time)
	if !ok {
		return
	}
	s.metrics.LoginDuration.WithLabelValues(provider, outcome).Observe(time.Since(start).Seconds())
}

// recordLoginFailure emits a login-failure audit event AND bumps the
// failure counter on the metrics registry (nil-safe). Reason is one of
// the Err* constants describing why authentication was refused.
func (s *Server) recordLoginFailure(ctx HandlerContext, clientID, provider, reason string) {
	if s.metrics != nil {
		s.metrics.LoginAttemptsTotal.WithLabelValues(provider, "failure").Inc()
	}
	s.observeLoginDuration(ctx, provider, "failure")
	s.dispatchLoginAnomaly(ctx, "", clientID, provider, "failure", reason)
	if s.auditor == nil {
		return
	}
	audit.RecordLoginFailure(s.auditor, ctx, clientID, provider, reason)
}

// dispatchLoginAnomaly hands a anomaly.LoginEvent to the AnomalyRunner.
// Nil-safe — no runner = no-op zero overhead. SubjectID is
// optional on failure paths (the credential validator may not
// have resolved a user); detectors needing it skip the subject-
// scoped checks.
func (s *Server) dispatchLoginAnomaly(ctx HandlerContext, subjectID, clientID, provider, outcome, failureReason string) {
	if s.anomalyRunner == nil {
		return
	}
	r := ctx.Request()
	event := &anomaly.LoginEvent{
		SubjectID:     subjectID,
		ClientID:      clientID,
		Provider:      provider,
		Outcome:       outcome,
		FailureReason: failureReason,
		RemoteIP:      audit.ClientIP(r),
		UserAgent:     r.Header.Get("User-Agent"),
		Timestamp:     time.Now(),
	}
	if info, ok := GeoFromHandlerContext(ctx); ok {
		event.Geo = info
	}
	if tp := r.Header.Get(HeaderTraceparent); tp != "" {
		if tc, err := tracer.ParseTraceparent(tp); err == nil {
			event.TraceID = tc.TraceID
		}
	}
	s.anomalyRunner.Dispatch(r.Context(), event)
}

// recordLoginSuccess emits a login event after a fully successful login flow
// AND bumps the success counter + tokens_issued counter on the metrics
// registry (nil-safe).
func (s *Server) recordLoginSuccess(ctx HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	if s.metrics != nil {
		s.metrics.LoginAttemptsTotal.WithLabelValues(provider, "success").Inc()
		s.metrics.TokensIssuedTotal.WithLabelValues(strategy).Inc()
	}
	s.observeLoginDuration(ctx, provider, "success")
	s.dispatchLoginAnomaly(ctx, userID, clientID, provider, "success", "")
	if s.auditor == nil {
		return
	}
	audit.RecordLoginSuccess(s.auditor, ctx, clientID, provider, strategy, userID, sessionID)
}

// recordLogout emits a logout event with what was actually revoked.
func (s *Server) recordLogout(ctx HandlerContext, sessionID string, revoked []string) {
	audit.RecordLogout(s.auditor, ctx, sessionID, revoked)
}

// recordLogoutNotifySuccess emits a `logout_notified` audit
// event for a successful back-channel logout fanout. ClientID is
// the RP that was notified; ActorID is the user whose logout
// triggered the notification.
func (s *Server) recordLogoutNotifySuccess(ctx HandlerContext, clientID, subject, uri string) {
	audit.RecordLogoutNotifySuccess(s.auditor, ctx, clientID, subject, uri)
}

// recordLogoutNotifyFailure emits a `logout_notified` audit
// event with Outcome=failure when the back-channel POST failed
// or the RP returned a non-2xx status. The error string lands
// in Reason so SIEMs can alert on patterns ("rp-X always 503").
func (s *Server) recordLogoutNotifyFailure(ctx HandlerContext, clientID, subject, reason string) {
	audit.RecordLogoutNotifyFailure(s.auditor, ctx, clientID, subject, reason)
}

// recordAccountLocked emits an account_locked audit event. Fires
// both when a NEW lockout engages (after the failure crossed the
// threshold) and when a subsequent attempt arrives while the
// lock is still active — operators want both signals to
// distinguish "lock just engaged" from "attacker keeps trying
// against a locked account". The lockoutKey lands in ActorID so
// SIEMs can pivot on it.
func (s *Server) recordAccountLocked(ctx HandlerContext, clientID, provider, lockKey string, until time.Time) {
	audit.RecordAccountLocked(s.auditor, ctx, clientID, provider, lockKey, until)
}

// recordCodeSent emits a code_sent event for two-step flows (phone/email).
// target is intentionally not stored in full to limit PII spread; only its
// type lives in Provider, the value goes into a short metadata key.
func (s *Server) recordCodeSent(ctx HandlerContext, provider, target string, ok bool) {
	audit.RecordCodeSent(s.auditor, ctx, provider, target, ok)
}

// recordTokenIssued emits a token_issued event (used for grant flows).
func (s *Server) recordTokenIssued(ctx HandlerContext, clientID, strategy, subjectID string) {
	audit.RecordTokenIssued(s.auditor, ctx, clientID, strategy, subjectID)
}

// recordRefreshTokenIssued emits a refresh_token_issued event. Set
// rotation=true on the rotation path so SIEMs can separate first-
// issue (login / authz_code) from rotation (refresh_token grant).
func (s *Server) recordRefreshTokenIssued(ctx HandlerContext, clientID, subjectID string, rotation bool) {
	audit.RecordRefreshTokenIssued(s.auditor, ctx, clientID, subjectID, rotation)
}

// recordIDTokenIssued emits an id_token_issued event whenever an
// OIDC id_token is appended to the response.
func (s *Server) recordIDTokenIssued(ctx HandlerContext, clientID, subjectID string) {
	audit.RecordIDTokenIssued(s.auditor, ctx, clientID, subjectID)
}

// recordDeviceCodeIssued emits a device_code_issued event at the
// start of an RFC 8628 device authorization grant.
func (s *Server) recordDeviceCodeIssued(ctx HandlerContext, clientID string) {
	audit.RecordDeviceCodeIssued(s.auditor, ctx, clientID)
}

// recordDeviceCodeApproved / Denied emit at the consent step.
// userID is the user who hit /device/verify; deviceClientID is the
// client_id that originally requested the device authorization.
func (s *Server) recordDeviceCodeDecision(ctx HandlerContext, userID, deviceClientID string, approved bool) {
	audit.RecordDeviceCodeDecision(s.auditor, ctx, userID, deviceClientID, approved)
}

// recordRefreshTokenReuse emits a refresh_token_reuse_detected event.
// Fired from the rotation grant when the store signals
// oauth.ErrRefreshTokenReused — a security signal worth routing to alerting.
func (s *Server) recordRefreshTokenReuse(ctx HandlerContext, clientID, familyID string, killed int) {
	audit.RecordRefreshTokenReuse(s.auditor, ctx, clientID, familyID, killed)
}

// itoa is a tiny strconv-free int formatter — keeps audit_handler.go
// free of a strconv import for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// recordCallbackFailure emits a callback_failure event.
func (s *Server) recordCallbackFailure(ctx HandlerContext, provider, reason string) {
	audit.RecordCallbackFailure(s.auditor, ctx, provider, reason)
}

// PathOIDCDiscovery is the OpenID Connect Discovery 1.0 metadata
// endpoint (also the de-facto location for RFC 8414 OAuth 2.0
// Authorization Server Metadata since most ecosystems collapsed them).
const PathOIDCDiscovery = "/.well-known/openid-configuration"

// oidcConfiguration mirrors OpenID Connect Discovery 1.0 §3 +
// RFC 8414 §2 fields. Optional fields are omitempty so the wire stays
// minimal — relying parties branch on presence per the spec.
type oidcConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`
	PushedAuthReqEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthReq  bool   `json:"require_pushed_authorization_requests,omitempty"`
	// RFC 9101 §10.5 — true when every registered client enforces
	// signed request objects (RequireSignedRequestObject=true on
	// the Client). Advertised AS-wide because the spec field is
	// boolean (no per-client surface in discovery). Stays false
	// when any client still accepts unsigned authorization
	// requests — matching the strictest-possible-promise semantics
	// the field implies.
	RequireSignedRequestObjectGlobal  bool     `json:"require_signed_request_object,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// RFC 8414 §2 + RFC 7662 §6: same set of client auth methods
	// the introspection endpoint accepts. The /token + /par +
	// /introspect + /revoke endpoints all share the same auth
	// pipeline in this server, so we advertise the same list on
	// each.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	// RFC 8414 §2 + RFC 7009 §4.1.2: same set for the revocation
	// endpoint.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	// RFC 9126 §5: client auth methods accepted on /par. Mirrors
	// the /token list since /par shares the same auth pipeline.
	PushedAuthorizationRequestEndpointAuthMethodsSupported []string `json:"pushed_authorization_request_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported                          []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsSupported                                        []string `json:"claims_supported,omitempty"`

	// RFC 9207 §3 — when true, this AS includes `iss` on every
	// authorization response (success + error). Constant true here
	// because handleLogin unconditionally stamps it via
	// authzErrorBody / resolveIssuer.
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`

	// RFC 9396 §13 — the union of every registered client's
	// AllowedAuthorizationDetailsTypes. Empty / omitted when no
	// client has declared a type allowlist (the parameter is
	// still accepted but unconstrained).
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// OIDC Back-Channel Logout 1.0 §2.1 — true when this server
	// will POST logout tokens to RPs' backchannel_logout_uri
	// endpoints. Set when both LogoutTokenIssuer + LogoutNotifier
	// are wired via WithBackchannelLogout.
	BackchannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`
	// BackchannelLogoutSessionSupported flips true when the AS
	// stamps `sid` in access + ID tokens — that is, when a
	// SessionManager is wired. Without a session manager every
	// token has empty sid, so advertising session support would
	// be a lie. With one wired, /end_session reads the sid from
	// the id_token_hint and forwards it on logout_tokens, letting
	// RPs invalidate the specific session rather than every
	// session for the subject.
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// OIDC Front-Channel Logout 1.0 §2.1 — true when at least one
	// registered client opts in via FrontchannelLogoutURI. The
	// server's /end_session handler then renders an HTML iframe
	// page instead of the bare 302/204 response. Per-client
	// metadata (the URI itself) is not advertised in discovery;
	// it's pre-registered out-of-band like every other client
	// secret.
	FrontchannelLogoutSupported bool `json:"frontchannel_logout_supported,omitempty"`
	// FrontchannelLogoutSessionSupported mirrors the back-channel
	// flag — true when SessionManager is wired so id_tokens
	// carry a sid claim the RP can correlate to its local
	// session at logout time.
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`

	// OIDC Core §3.1.2.1 — the prompt values this AS understands.
	// "none" enables silent renewal via id_token_hint; the others
	// are accepted but currently lower the request to its default
	// interactive path (login/consent/select_account UIs aren't
	// rendered by this server, only their downstream signaling).
	PromptValuesSupported []string `json:"prompt_values_supported,omitempty"`

	// OIDC Core §3.1.2.1 + Form Post Response Mode 1.0 — the
	// response delivery modes this AS supports for authorization
	// responses. `form_post` triggers the HTML auto-POST page;
	// `query` / `fragment` are accepted but currently just
	// influence the response shape the RP's own JS handles
	// (this server is JSON-bodied for /auth/login by default).
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// OIDC Core §5.5 — true when the AS accepts the `claims`
	// request parameter. Always true here (the parameter is
	// validated for JSON-object shape and threaded into
	// AuthRequest.RequestedClaims; authenticators / issuers that
	// honor it project the requested claims into output).
	ClaimsParameterSupported bool `json:"claims_parameter_supported"`

	// OIDC Core §5.3.2 — JWS algs supported for signing /userinfo
	// responses when the client's `userinfo_signed_response_alg`
	// metadata is set. Empty / omitted = signed userinfo not
	// available (the oidc.IDTokenIssuer doesn't implement oidc.UserinfoSigner).
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// RFC 9449 §5.1 — JWS algs accepted on the DPoP proof
	// header. Always EdDSA today (matches every other JWT path
	// on this server). Presence of the field signals the AS
	// supports DPoP at all.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// RFC 8705 §3.3 — true when the AS supports issuing tokens
	// bound to mTLS client certificates. Flipped when
	// WithClientCertExtractor is wired.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// RFC 8705 §5 — when the AS terminates mTLS on a different
	// hostname / port than the standard endpoints (typical edge:
	// `auth.example.com` for bearer flows, `mtls.example.com` for
	// cert-authenticated flows), publish the alternates here.
	// RPs that need cert-bound issuance route to the alias; plain
	// bearer continues hitting the regular endpoints. This server
	// publishes the same endpoint URLs on both sides today (the
	// HTTPS server accepts certs on every endpoint), so RPs see
	// identical hostnames but the field's presence signals "mTLS
	// is operationally available." Operators with split-hostname
	// terminations override via deploy-side proxy rewriting.
	MTLSEndpointAliases *MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`

	// OIDC Discovery §3 `acr_values_supported`. Populated from
	// the operator-declared `WithSupportedACRValues` — empty /
	// omitted when no list is configured. RPs branching on ACR
	// (step-up auth, FAPI 2.0) use this to validate what they
	// can request from the AS.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// OIDC Discovery §3 operator metadata. Pointed at by RPs
	// during consent ("by signing in you accept ..." linking to
	// op_policy_uri / op_tos_uri) and used by integrators looking
	// up the AS's own SDK reference (service_documentation).
	// Populated via `WithOperatorMetadata`; omitted when unset.
	OpPolicyURI          string `json:"op_policy_uri,omitempty"`
	OpTosURI             string `json:"op_tos_uri,omitempty"`
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// OIDC Discovery §3 `claim_types_supported`. RPs introspect
	// what claim shapes the AS emits — "normal" (claims are
	// inline in the id_token / userinfo response), "aggregated"
	// (claims arrive as a JWT inside the response), "distributed"
	// (claims at a fetchable URL). This server only emits the
	// inline normal form; advertised as ["normal"] for spec
	// completeness so OIDC conformance suites pass without
	// inferring the default.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// OIDC Core §3.1.2.1 `display` parameter — values RPs may pass
	// to hint the auth UI form factor (page / popup / touch / wap).
	// This server renders no chrome itself (authenticators own the
	// UI), but advertises "page" — the spec default — so OIDC
	// conformance suites don't have to infer it. RPs requesting
	// other values get the same default path; the parameter is
	// accepted on the wire without being acted on.
	DisplayValuesSupported []string `json:"display_values_supported,omitempty"`

	// OIDC Core §9 — JWS algorithms the AS accepts on the
	// `client_assertion` JWT for `private_key_jwt` client
	// authentication. RPs introspect this to know which alg to
	// sign their assertion with. Matches the same EdDSA-only
	// surface JAR + DPoP advertise.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// Same JWS algorithm advertisement for the introspect /
	// revoke / PAR endpoints — all share the JWT-assertion path
	// so they accept the same alg set.
	IntrospectionEndpointAuthSigningAlgValuesSupported              []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported                 []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported []string `json:"pushed_authorization_request_endpoint_auth_signing_alg_values_supported,omitempty"`

	// RFC 9101 §10.5 — true when the `request` parameter is
	// accepted on /auth/login. Always true here.
	RequestParameterSupported bool `json:"request_parameter_supported"`
	// RequestURIParameterSupported reflects whether the AS accepts
	// `request_uri` as an HTTPS URL it will fetch (RFC 9101 §5.2.2)
	// — flipped true when `WithJARFetcher` is wired. The PAR
	// `urn:ietf:params:oauth:request_uri:` prefix is ALWAYS accepted
	// when a oauth.PARStore is wired (advertised separately via
	// pushed_authorization_request_endpoint).
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
	// RequestObjectSigningAlgValuesSupported lists the alg values
	// the JAR verifier accepts on the request JWT. EdDSA today.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RFC 9101 §6.4 encrypted JAR. Populated when WithJARDecrypter
	// is wired — the SupportedAlgs() / SupportedEncs() the decrypter
	// reports surface here so RPs know which alg + enc to use when
	// constructing the JWE. Omitted (the fields disappear from the
	// JSON) when no decrypter is wired; encrypted requests are
	// rejected with invalid_request_object in that case.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// RFC 8414 §2.1 — when set, contains a JWS over the same
	// metadata claims as the surrounding document. RPs MUST verify
	// the signature with JWKS before trusting any endpoint; if the
	// signed_metadata fields disagree with the plaintext, the
	// signed payload wins. Wired via `WithMetadataSigner` — left
	// empty (and field omitted) when no signer is plugged in.
	SignedMetadata string `json:"signed_metadata,omitempty"`

	// MFA orchestration (SnapLink extension; non-standard). When
	// [WithMFAProvider] + [WithMFAChallengeStore] are wired, MFAEndpoint
	// points at /auth/mfa and MFAMethodsSupported lists the factor
	// names the provider can verify. Discovery clients branch on the
	// presence of MFAEndpoint to know whether to handle the
	// mfa_required response shape. Fields omitted from the JSON when
	// MFA is not wired (preserves wire-shape parity with vanilla OIDC
	// discovery for callers that don't speak the extension).
	MFAEndpoint         string   `json:"mfa_endpoint,omitempty"`
	MFAMethodsSupported []string `json:"mfa_methods_supported,omitempty"`
}

// MTLSEndpointAliases is the RFC 8705 §5 alias map. Only endpoints
// that participate in client authentication / token issuance need
// alternates; discovery, JWKS, and end_session aren't gated on mTLS.
// Empty fields are omitted from the JSON output so the structure
// stays compact for deployments that publish a subset of endpoints.
type MTLSEndpointAliases struct {
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`
	PushedAuthReqEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
}

// codeChallengeMethodsFor advertises the PKCE methods this AS will
// actually accept. OAuth 2.1 strict mode forbids `plain` server-wide
// (RFC 7636 §4.2 marks it weaker; 2.1 §7.5.2 mandates S256), so the
// codeChallengeMethodsFor / responseTypesFor / subjectTypesFor delegate
// to oidc.* — see oidc/discovery_options.go for the OAuth 2.1 strict
// reasoning + pairwise-advertise gate.
func codeChallengeMethodsFor(s *Server) []string {
	return oidc.CodeChallengeMethodsFor(s.oauth21Strict)
}

func responseTypesFor(s *Server) []string {
	return oidc.ResponseTypesFor(s.oauth21Strict)
}

func subjectTypesFor(s *Server) []string {
	return oidc.SubjectTypesFor(s.pairwiseStore != nil)
}

// signDiscoveryMetadata marshals cfg to JSON with SignedMetadata
// cleared, re-parses as a claim map, and asks the wired
// oidc.MetadataSigner to JWS it. The signed payload must equal the
// plaintext fields per RFC 8414 §2.1; we enforce that by sourcing
// the claims from the same struct, with one round-trip through
// json (Marshal + Unmarshal) to get the map shape the signer
// expects.
func (s *Server) signDiscoveryMetadata(ctx context.Context, cfg *oidcConfiguration) (string, error) {
	if s.metadataSigner == nil {
		return "", nil
	}
	saved := cfg.SignedMetadata
	cfg.SignedMetadata = ""
	defer func() { cfg.SignedMetadata = saved }()
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", err
	}
	return s.metadataSigner.SignMetadata(ctx, claims)
}

// Both `require_signed_request_object` (RFC 9101 §10.5) and
// `require_pushed_authorization_requests` (RFC 9126 §5) derive from
// scanning the client store. They share the cached
// clientDiscoverySnapshot so a single iteration powers every
// derivation across one discovery doc request.

// handleOIDCDiscovery serves the OpenID Connect Discovery 1.0 +
// RFC 8414 metadata document. Always wired by Mount (no opt-in
// option) — relying parties expect this endpoint at a fixed URL
// per the spec.
//
// Absolute URLs are derived from the incoming request (scheme +
// host) so the same SSO server can be advertised under multiple
// hostnames without a per-deployment base-URL configuration knob.
// Operators behind a TLS-terminating proxy MUST forward
// X-Forwarded-Proto so the discovery endpoint advertises https,
// not http — otherwise OIDC RPs refuse the issuer per §4.3.
func (s *Server) handleOIDCDiscovery(ctx HandlerContext) {
	base := requestBaseURL(ctx.Request())
	// Body cache: skip the marshal + struct assembly when a recent
	// rendering for this base URL is still fresh. Keyed by base URL
	// so multi-host SSO doesn't conflate. Honors If-None-Match so
	// well-behaved RP libraries can short-circuit to 304.
	if s.discoveryDocCacheTTL > 0 {
		if entry := s.lookupDiscoveryDocCache(base); entry != nil {
			s.writeDiscoveryDoc(ctx, entry)
			return
		}
	}
	// Single client-store iteration powers every derived field below
	// (scopes union, RequirePAR-any, RequireSignedRequestObject-all,
	// frontchannel_logout_supported, authorization_details types
	// union). TTL-cached across requests so a hot RP polling the
	// discovery doc doesn't pay 5× ClientStore.List per call.
	clientSnap := s.discoverySnapshot(ctx.Request().Context())
	cfg := oidcConfiguration{
		Issuer:                 base,
		AuthorizationEndpoint:  base + PathLogin,
		TokenEndpoint:          base + PathToken,
		UserInfoEndpoint:       base + PathUserInfo,
		JWKSURI:                base + PathJWKS,
		EndSessionEndpoint:     base + PathEndSession,
		RevocationEndpoint:     base + PathRevoke,
		IntrospectionEndpoint:  base + PathIntrospect,
		ResponseTypesSupported: responseTypesFor(s),
		GrantTypesSupported:    append([]string(nil), SupportedGrants...),
		SubjectTypesSupported:  subjectTypesFor(s),
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt", // RFC 7521 + 7523
			// RFC 6749 §2.1 / OIDC Core §9 — public clients (SPAs,
			// native apps) authenticate only by client_id + PKCE,
			// so `none` is the spec-defined method for them. DCR
			// already accepts it (handle_register.go), so advertise
			// it here so RP libraries don't reject the AS during
			// metadata validation.
			"none",
		},
		// Introspection + revocation share the same client-auth
		// pipeline as /token, so advertise the same list.
		IntrospectionEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
		},
		RevocationEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
		},
		CodeChallengeMethodsSupported: codeChallengeMethodsFor(s),
		// RFC 9207 §3: this server always includes `iss` in
		// authorization responses (see handleLogin + resolveIssuer).
		AuthorizationResponseIssParameterSupported: true,
		// RFC 9101 §10.5: JAR `request` parameter accepted; URL
		// fetched `request_uri` flips true when WithJARFetcher is
		// wired (set below).
		RequestParameterSupported:              true,
		RequestURIParameterSupported:           false,
		RequestObjectSigningAlgValuesSupported: []string{"EdDSA"},
		ClaimsParameterSupported:               true,
	}
	if s.jarFetcher != nil {
		cfg.RequestURIParameterSupported = true
	}
	if s.jarDecrypter != nil {
		// Advertising the alg + enc lists tells RPs which JWE shapes
		// the AS will accept on the `request` parameter. RPs that don't
		// see these fields know to fall back to plain JWS JAR (which
		// is always accepted).
		cfg.RequestObjectEncryptionAlgValuesSupported = s.jarDecrypter.SupportedAlgs()
		cfg.RequestObjectEncryptionEncValuesSupported = s.jarDecrypter.SupportedEncs()
	}
	// MFA orchestration is advertised only when both Provider + Store
	// are wired — having Provider without Store would be a misconfig
	// (handleMFAComplete returns 404 in that state) so we don't leak
	// the endpoint into discovery either.
	if s.mfaProvider != nil && s.mfaChallengeStore != nil {
		cfg.MFAEndpoint = base + PathMFAComplete
		cfg.MFAMethodsSupported = s.mfaProvider.SupportedMethods()
	}
	// When the operator overrode the issuer name with WithIssuer, prefer
	// that — many production deployments set issuer to the canonical
	// public URL even when the SSO server is internally reachable at a
	// different host.
	if s.issuer != "" && s.issuer != DefaultIssuer {
		cfg.Issuer = s.issuer
	}
	if s.idTokenIssuer != nil {
		// We always sign with EdDSA today; when more signers land this
		// list should reflect every registered signature algorithm.
		cfg.IDTokenSigningAlgValuesSupported = []string{"EdDSA"}
		// Userinfo signing capability is gated on the issuer
		// implementing the oidc.UserinfoSigner extension. The default
		// Ed25519JWTIssuer does — third-party implementations may
		// not, and the omitempty serialization correctly hides the
		// claim in that case.
		if _, ok := s.idTokenIssuer.(oidc.UserinfoSigner); ok {
			cfg.UserinfoSigningAlgValuesSupported = []string{"EdDSA"}
		}
	}
	if s.parStore != nil {
		// RFC 9126 §5: advertise the PAR endpoint so RPs that prefer
		// the pushed-request flow can discover it. The server-wide
		// `require_pushed_authorization_requests` discovery flag is
		// flipped when ANY registered client has RequirePAR=true —
		// matches the OIDC convention where a discovery boolean
		// reflects "is this supported anywhere".
		cfg.PushedAuthReqEndpoint = base + PathPAR
		cfg.PushedAuthorizationRequestEndpointAuthMethodsSupported = []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
		}
		if clientSnap.requirePAR {
			cfg.RequirePushedAuthReq = true
		}
	}
	if s.dcrPolicy != nil {
		// RFC 7591 §3: advertise the registration endpoint so
		// dynamic clients can discover it. The initial access
		// token (when required) is distributed out-of-band, not
		// via discovery.
		cfg.RegistrationEndpoint = base + oauth.PathRegister
	}
	if len(clientSnap.scopes) > 0 {
		cfg.ScopesSupported = clientSnap.scopes
	}
	if len(clientSnap.authorizationDetailTypes) > 0 {
		cfg.AuthorizationDetailsTypesSupported = clientSnap.authorizationDetailTypes
	}
	if s.logoutTokenIssuer != nil && s.logoutNotifier != nil {
		cfg.BackchannelLogoutSupported = true
		if s.sessionMgr != nil {
			cfg.BackchannelLogoutSessionSupported = true
		}
	}
	if clientSnap.frontchannelLogout {
		cfg.FrontchannelLogoutSupported = true
		if s.sessionMgr != nil {
			cfg.FrontchannelLogoutSessionSupported = true
		}
	}
	cfg.ClaimsSupported = []string{
		"sub", "iss", "aud", "exp", "iat", "nbf", "scope",
		"nonce", "auth_time", "amr", "acr", "azp",
	}
	// DPoP advertisement is unconditional — the handler accepts
	// the `DPoP` header on /token whenever it's present; there's
	// no opt-in store to wire.
	cfg.DPoPSigningAlgValuesSupported = []string{"EdDSA"}
	if s.clientCertExtractor != nil {
		cfg.TLSClientCertificateBoundAccessTokens = true
		cfg.MTLSEndpointAliases = &MTLSEndpointAliases{
			TokenEndpoint:         cfg.TokenEndpoint,
			RevocationEndpoint:    cfg.RevocationEndpoint,
			IntrospectionEndpoint: cfg.IntrospectionEndpoint,
			UserInfoEndpoint:      cfg.UserInfoEndpoint,
			RegistrationEndpoint:  cfg.RegistrationEndpoint,
			PushedAuthReqEndpoint: cfg.PushedAuthReqEndpoint,
		}
	}
	if len(s.supportedACRValues) > 0 {
		cfg.ACRValuesSupported = append([]string(nil), s.supportedACRValues...)
	}
	cfg.OpPolicyURI = s.opPolicyURI
	cfg.OpTosURI = s.opTosURI
	cfg.ServiceDocumentation = s.serviceDocumentation
	cfg.ClaimTypesSupported = []string{"normal"}
	cfg.DisplayValuesSupported = []string{"page"}
	if clientSnap.requireSignedRequestObject {
		cfg.RequireSignedRequestObjectGlobal = true
	}
	cfg.TokenEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	cfg.IntrospectionEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	cfg.RevocationEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	if s.parStore != nil {
		cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	}
	// OIDC Core §3.1.2.1 — advertise "none" so SPAs know they can
	// run silent renewal via id_token_hint. The other prompt
	// values (login / consent / select_account) aren't surfaced
	// today because this server doesn't render those UIs itself;
	// the RP is responsible for the interactive flow.
	cfg.PromptValuesSupported = []string{PromptNone}

	// Form Post Response Mode 1.0: every shape this server can
	// emit. `form_post` is the value-add (auto-POST HTML page);
	// query + fragment are advertised for spec completeness so
	// RPs that introspect discovery know they're accepted on
	// the wire.
	cfg.ResponseModesSupported = []string{
		ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost,
	}

	// RFC 8414 §2.1 signed_metadata MUST be produced AFTER every
	// other field is finalized so the signed claims match what RPs
	// see in the plaintext fields. The signing itself excludes the
	// signed_metadata field (chicken-and-egg) — claims are sourced
	// from the cfg struct via json round-trip.
	if s.metadataSigner != nil {
		if jws, err := s.signDiscoveryMetadata(ctx.Request().Context(), &cfg); err != nil {
			s.logger.Error("signed_metadata generation failed", "error", err)
		} else {
			cfg.SignedMetadata = jws
		}
	}

	// ttl <= 0 disables both in-process caching AND the response-side
	// ETag / Cache-Control headers — every request renders fresh and
	// downstream caches (CDN, RP libraries) are told not to cache.
	if s.discoveryDocCacheTTL <= 0 {
		ctx.JSON(http.StatusOK, cfg)
		return
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		s.logger.Error("discovery marshal failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	entry := buildDiscoveryDocEntry(body, s.discoveryDocCacheTTL)
	s.storeDiscoveryDocCache(base, entry)
	s.writeDiscoveryDoc(ctx, entry)
}

// requestBaseURL delegates to middleware.BaseURL — see that function
// for the X-Forwarded-Proto / X-Forwarded-Host edge trust contract.
func requestBaseURL(r *http.Request) string { return middleware.BaseURL(r) }

// JWK + JWKSProvider + PathJWKS + DefaultJWKSCacheMaxAge moved to core/jwks.go
// (data type / interface / wire constants).

// handleSilentRenewal implements OIDC Core §3.1.2.1's prompt=none flow.
// The RP loads /auth/login in a hidden iframe with prompt=none +
// id_token_hint to probe whether the End-User still has an active
// session — when yes, a freshly minted access (and id) token returns
// without any UI; when no, error login_required tells the iframe to
// fall back to the visible login flow.
//
// Spec checkpoints satisfied here:
//
//   - §3.1.2.1: prompt=none MUST NOT be combined with other prompt
//     values (caller validated this).
//   - §3.1.2.6: missing or unverifiable id_token_hint → login_required.
//   - §3.1.2.6: no active End-User session → login_required.
//   - §3.1.2.6: hint subject doesn't match the live session → login_required.
//   - The new ID token's `auth_time` MUST equal the original — no fresh
//     authentication event happened, so the factor freshness signal
//     downstream services see is preserved (RFC 9068 §2.2).
//
// Returns true when the silent flow handled the response (caller MUST
// bail). False on a non-prompt-none request (caller continues).
// handleSilentRenewal delegates to oidc.HandleSilentRenewal — see
// that file for the OIDC Core §3.1.2.1 prompt=none flow.
func (s *Server) handleSilentRenewal(ctx HandlerContext, prompts []string, req oidc.SilentRenewalRequest, client *Client) bool {
	return oidc.HandleSilentRenewal(s, ctx, prompts, req, client)
}

// defaultDiscoveryCacheTTL is the freshness window for client-store-
// derived discovery fields. 5 seconds is short enough that DCR /
// admin client edits visibly propagate (humans typically wait > 5s
// before refreshing the discovery doc) and long enough that a busy
// RP polling /.well-known/openid-configuration N times per second
// doesn't pay 5× ClientStore.List per request. When 0, the cache is
// disabled entirely (legacy behavior).
const defaultDiscoveryCacheTTL = 5 * time.Second

// clientDiscoverySnapshot memoizes the discovery-doc fields that
// derive from iterating the entire client store. Computing them
// requires one ClientStore.List + a pass per derivation; without
// caching, every /.well-known/openid-configuration hit pays 5×
// List + 5× iteration. With caching, the cost amortizes across the
// TTL window.
//
// IMPORTANT: every field here MUST be safe to read concurrently
// after the snapshot is published via atomic.Pointer. We copy slices
// at compute-time so downstream readers can't mutate the snapshot
// in place.
type clientDiscoverySnapshot struct {
	requirePAR                 bool
	requireSignedRequestObject bool
	frontchannelLogout         bool
	scopes                     []string
	authorizationDetailTypes   []string
	expiresAt                  time.Time
}

// WithDiscoveryCacheTTL overrides the freshness window for the
// client-store-derived discovery fields. Pass 0 to disable the
// cache (every request re-iterates the client store — useful when
// running in a hot-reload dev loop where DCR edits must reflect
// instantly). Defaults to defaultDiscoveryCacheTTL.
func WithDiscoveryCacheTTL(d time.Duration) Option {
	return func(s *Server) { s.discoveryCacheTTL = d }
}

// discoverySnapshot returns the current client-store-derived snapshot,
// refreshing it via single-flight when stale or absent. Safe for
// concurrent use. When the client store is unavailable or returns
// an error, the snapshot has empty/false fields (the legacy
// "degraded discovery" behavior) — discovery MUST keep serving even
// when the store is sick.
func (s *Server) discoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	ttl := s.discoveryCacheTTL
	if ttl == 0 {
		// Caching disabled — compute every time. The single-flight
		// path is bypassed so dev-loop hot-reload sees DCR edits
		// instantly.
		return s.computeDiscoverySnapshot(ctx)
	}
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	// Re-check after acquiring the lock — a peer may have refreshed
	// while we waited. Standard double-checked-locking pattern.
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	snap := s.computeDiscoverySnapshot(ctx)
	s.discoveryCache.Store(snap)
	return snap
}

// computeDiscoverySnapshot does the expensive client-store iteration
// once and projects all four derived fields. Splitting compute from
// the cache wrapper lets tests assert the projection directly
// without poking the cache.
func (s *Server) computeDiscoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	snap := &clientDiscoverySnapshot{expiresAt: time.Now().Add(s.discoveryCacheTTL)}
	if s.idTokenIssuer != nil {
		snap.scopes = []string{ScopeOpenID}
	}
	if s.clientStore == nil {
		return snap
	}
	clients, err := s.clientStore.List(ctx)
	if err != nil {
		return snap
	}
	scopesSeen := map[string]struct{}{}
	if s.idTokenIssuer != nil {
		scopesSeen[ScopeOpenID] = struct{}{}
	}
	adTypesSeen := map[string]struct{}{}
	allRequireSignedRequestObject := len(clients) > 0
	for _, c := range clients {
		if c == nil {
			allRequireSignedRequestObject = false
			continue
		}
		if c.RequirePAR {
			snap.requirePAR = true
		}
		if !c.RequireSignedRequestObject {
			allRequireSignedRequestObject = false
		}
		if c.FrontchannelLogoutURI != "" {
			snap.frontchannelLogout = true
		}
		for _, sc := range c.AllowedScopes {
			if sc != "" {
				scopesSeen[sc] = struct{}{}
			}
		}
		for _, t := range c.AllowedAuthorizationDetailsTypes {
			if t != "" {
				adTypesSeen[t] = struct{}{}
			}
		}
	}
	snap.requireSignedRequestObject = allRequireSignedRequestObject
	snap.scopes = sortedKeys(scopesSeen)
	if len(adTypesSeen) > 0 {
		snap.authorizationDetailTypes = sortedKeys(adTypesSeen)
	}
	return snap
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultDiscoveryDocCacheTTL re-exports oidc.DefaultDocCacheTTL for
// backward compat. See oidc/discovery_doc_cache.go for the full
// semantics + the CDN-aware tuning notes.
const DefaultDiscoveryDocCacheTTL = oidc.DefaultDocCacheTTL

// discoveryDocEntry aliases oidc.DocEntry so the Server cache holds
// the canonical type without exporting it from this package.
type discoveryDocEntry = oidc.DocEntry

// buildDiscoveryDocEntry delegates to oidc.BuildDocEntry.
func buildDiscoveryDocEntry(body []byte, ttl time.Duration) *discoveryDocEntry {
	return oidc.BuildDocEntry(body, ttl)
}

// lookupDiscoveryDocCache returns a fresh cached entry for base, or
// nil to signal "render fresh". The sync.Map keeps reads lock-free
// in the hot path.
func (s *Server) lookupDiscoveryDocCache(base string) *discoveryDocEntry {
	v, ok := s.discoveryDocCache.Load(base)
	if !ok {
		return nil
	}
	entry, _ := v.(*discoveryDocEntry)
	if entry.Fresh() {
		return entry
	}
	// Stale — drop so the next caller re-renders.
	s.discoveryDocCache.Delete(base)
	return nil
}

func (s *Server) storeDiscoveryDocCache(base string, entry *discoveryDocEntry) {
	s.discoveryDocCache.Store(base, entry)
}

// writeDiscoveryDoc delegates to oidc.WriteDoc with the server's
// configured cache TTL.
func (s *Server) writeDiscoveryDoc(ctx HandlerContext, entry *discoveryDocEntry) {
	oidc.WriteDoc(ctx, entry, s.discoveryDocCacheTTL)
}

// WithDiscoveryDocCacheTTL configures how long a rendered discovery
// document body may serve from cache. ttl <= 0 disables body caching
// (snapshot caching via [WithDiscoveryCacheTTL] continues independently).
// Default is [DefaultDiscoveryDocCacheTTL].
func WithDiscoveryDocCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.discoveryDocCacheTTL = ttl }
}

// OIDC + RFC 9207 response-shaping helpers. Three concerns clustered
// here for navigability:
//
//   1. resolveIssuer + authzErrorBody* — RFC 9207 issuer-identification
//      stamping on every authorization-endpoint response.
//   2. renderFormPostResponse + helpers — OIDC Form Post Response Mode 1.0
//      auto-submit HTML for response_mode=form_post.
//   3. maybeSignUserInfo — OIDC userinfo signed-response (JWT) path.
//
// All three live on *Server because they reach into Server fields
// (issuer, idTokenIssuer, clientStore, logger).

// -----------------------------------------------------------------------------
// RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification.
//
// Defense against mix-up attacks: when a client is configured with
// multiple authorization servers, an attacker can attempt to trick the
// client into accepting an authorization response from one AS as if it
// came from another. Including the AS issuer identifier in every
// authorization response lets the client verify "this code/token came
// from the AS I expected" before redeeming the code at the token
// endpoint.
//
// RFC 9207 §2 is written for redirect-based responses (`?iss=...`
// query param on the redirect to the RP). This server's /auth/login is
// a BFF-shaped JSON endpoint rather than a 302-redirect endpoint; the
// adaptation is to include `iss` in the JSON response body alongside
// `code` / `state` / `error`. A client that builds the redirect URI
// on the SPA side can propagate the value into `iss=...` as the spec
// intends.

// resolveIssuer returns the issuer identifier this server stamps in
// authorization responses. Matches the value advertised in the OIDC
// discovery document: operator-configured `WithIssuer` value when set
// and not the default sentinel; otherwise the request's base URL.
//
// Critical invariant: the value returned here MUST equal
// `oidcConfiguration.Issuer` for the same request — RFC 9207 §2
// requires the `iss` parameter to be the same identifier the AS
// publishes via discovery, so a client comparing them detects mix-up.
func (s *Server) resolveIssuer(ctx HandlerContext) string {
	if s.issuer != "" && s.issuer != DefaultIssuer {
		return s.issuer
	}
	return requestBaseURL(ctx.Request())
}

// authzErrorBody returns the standard error envelope for an
// authorization endpoint response with `iss` stamped per RFC 9207 §2.
// Use this in handleLogin (and any future authorization endpoint) —
// NOT in token / userinfo / callback handlers, which are not
// authorization responses.
func (s *Server) authzErrorBody(ctx HandlerContext, code string) map[string]string {
	return map[string]string{
		KeyError: code,
		KeyIss:   s.resolveIssuer(ctx),
	}
}

// authzErrorBodyDesc is authzErrorBody plus an error_description.
func (s *Server) authzErrorBodyDesc(ctx HandlerContext, code, desc string) map[string]string {
	return map[string]string{
		KeyError:            code,
		KeyErrorDescription: desc,
		KeyIss:              s.resolveIssuer(ctx),
	}
}

// -----------------------------------------------------------------------------
// OpenID Connect Form Post Response Mode 1.0.
//
// The RP requests `response_mode=form_post` when it wants the
// authorization response delivered as an HTML auto-submitted POST
// to its redirect_uri, rather than the default query-string redirect.
// Useful for RPs that handle POST bodies more naturally than parsing
// fragment / query parameters, and for delivering longer responses
// (id_token, etc.) without URL-length limits.
//
// Spec: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
//
// This implementation:
//   - Renders a minimal HTML document with a hidden form whose body
//     POSTs {code, state, iss} to redirect_uri.
//   - Auto-submits via a body onload handler — operators using strict
//     CSP that blocks inline event handlers should serve this
//     endpoint outside their CSP middleware OR allowlist a 'self'
//     script-src for /auth/login.
//   - Provides a manual submit button inside <noscript> so RPs that
//     disable JS still see a fallback (the user clicks once).
//   - All response values pass through html/template's
//     auto-escaping (URL context for action=, attribute context for
//     value=), so an attacker can't break out of the form fields.
//   - Hardens response headers: X-Frame-Options: DENY (clickjacking)
//     + Cache-Control: no-store + Referrer-Policy: no-referrer
//     (don't leak the AS's URL to the RP via Referer; the auth
//     response itself is what the RP needs).

// ResponseModeFormPost is the OIDC Form Post Response Mode 1.0
// magic string for the `response_mode` parameter.
const ResponseModeFormPost = "form_post"

// ResponseModeQuery is the default response_mode for response_type=code
// per OIDC Core §3.1.2.5: parameters appended to the redirect_uri's
// query string.
const ResponseModeQuery = "query"

// ResponseModeFragment is the default response_mode for token-bearing
// response types (implicit flow). Parameters delivered after `#`.
const ResponseModeFragment = "fragment"

// renderFormPostResponse delegates to oidc.RenderFormPostResponse —
// the template + escaping contract lives there.
func (s *Server) renderFormPostResponse(ctx HandlerContext, redirectURI, code, state string) {
	oidc.RenderFormPostResponse(ctx, redirectURI, code, state, s.resolveIssuer(ctx))
}

// isValidResponseMode delegates to oidc.IsValidResponseMode.
func isValidResponseMode(mode string) bool { return oidc.IsValidResponseMode(mode) }

// maybeSignUserInfo delegates to oidc.MaybeSignUserInfo — see that
// function for the EdDSA-only + UserinfoSigner type-assert gate.
func (s *Server) maybeSignUserInfo(ctx HandlerContext, clientID string, body map[string]any) bool {
	return oidc.MaybeSignUserInfo(s, ctx, clientID, body)
}

// Permission handlers (delegators — bodies in permissions/handlers.go).
func (s *Server) handleMyPermissions(ctx HandlerContext) { permissions.HandleMyPermissions(s, ctx) }
func (s *Server) handleMyRoles(ctx HandlerContext)       { permissions.HandleMyRoles(s, ctx) }
func (s *Server) handleMyMenus(ctx HandlerContext)       { permissions.HandleMyMenus(s, ctx) }

func (s *Server) resolvePermissionsForLogin(ctx context.Context, userID, clientID string) ([]permissions.Role, []permissions.Permission, permissions.MenuTree) {
	return permissions.ResolveForLogin(s.permissions, s.logger, ctx, userID, clientID)
}

func (s *Server) recordPermissionQuery(ctx HandlerContext, userID, clientID, kind string, ok bool) {
	permissions.RecordQuery(s.auditor, ctx, userID, clientID, kind, ok)
}

// AuthenticatedSubject exposes authenticatedSubject for handlers/ subpackages
// (Deps interface needs it as an exported method).
func (s *Server) AuthenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	return s.authenticatedSubject(ctx)
}

// Audit handlers (delegators — bodies in audit/handlers.go).
func (s *Server) handleAuditEvents(ctx HandlerContext)    { audit.HandleEvents(s, ctx) }
func (s *Server) handleAuditEventByID(ctx HandlerContext) { audit.HandleEventByID(s, ctx) }

// JWKS handler (delegator — body in oidc/handlers.go).
func (s *Server) handleJWKS(ctx HandlerContext) { oidc.HandleJWKS(s, ctx) }
