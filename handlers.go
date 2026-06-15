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
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/federation"
	"github.com/snaplink/sso/metering"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
	"github.com/snaplink/sso/tenant"
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
//
// handlePAR delegates to oauth.HandlePAR — see that file for the
// RFC 9126 pre-redirect client authentication + validation flow.
func (s *Server) handlePAR(ctx HandlerContext) { oauth.HandlePAR(s, ctx) }

// handleBackchannelAuth delegates to oauth.HandleBackchannelAuth —
// see that file for the OIDC CIBA Core 1.0 poll-mode flow.
func (s *Server) handleBackchannelAuth(ctx HandlerContext) { oauth.HandleBackchannelAuth(s, ctx) }

// ResolveCIBAHint maps a CIBA request's hints to a known user's subject
// id. Poll mode: at least one hint must resolve. login_hint is matched
// against UserProvider.GetByID (the canonical identifier); id_token_hint
// is validated and its sub trusted; login_hint_token is treated as an
// opaque GetByID lookup. Returns ("", nil) when nothing resolves — the
// handler collapses that to unknown_user_id (anti-enumeration). The
// provider name is recorded for the AMR claim ("ciba" — out-of-band
// confirmation).
func (s *Server) ResolveCIBAHint(ctx context.Context, loginHint, idTokenHint, loginHintToken string) (string, string, error) {
	// id_token_hint: validate the token and trust its subject. The
	// validator rejects expired / wrong-alg / bad-signature tokens.
	if idTokenHint != "" {
		if claims, err := s.ValidateToken(ctx, idTokenHint); err == nil && claims != nil && claims.Subject != "" {
			return claims.Subject, CIBAAMR, nil
		}
	}
	if s.userProvider == nil {
		return "", "", nil
	}
	for _, hint := range []string{loginHint, loginHintToken} {
		if hint == "" {
			continue
		}
		if u, err := s.userProvider.GetByID(ctx, hint); err == nil && u != nil {
			return u.ID, CIBAAMR, nil
		}
	}
	return "", "", nil
}

// CIBAAMR is the AMR / provider value recorded for a token minted via
// the CIBA grant — the user confirmed out of band on a separate
// authentication device.
const CIBAAMR = "ciba"

// DeliverCIBAChallenge pushes the auth_req_id out of band via the wired
// CIBA transport. binding_message is forwarded under the metadata key
// so the device app can render it for the user to correlate.
func (s *Server) DeliverCIBAChallenge(ctx context.Context, authReqID, subjectID, bindingMessage string) error {
	if s.cibaTransport == nil {
		return oauth.ErrCIBARequestInvalid
	}
	var meta map[string]string
	if bindingMessage != "" {
		meta = map[string]string{"binding_message": bindingMessage}
	}
	return s.cibaTransport.Send(ctx, authReqID, subjectID, meta)
}

// RecordCIBAAuthRequest emits the ciba_auth_request audit event.
func (s *Server) RecordCIBAAuthRequest(ctx HandlerContext, clientID, subjectID, authReqID string) {
	audit.RecordCIBAAuthRequest(s.auditor, ctx, clientID, subjectID, authReqID)
}

// recordCIBADecision emits a ciba_approved / ciba_denied audit event.
func (s *Server) recordCIBADecision(ctx HandlerContext, clientID, subjectID string, approved bool) {
	audit.RecordCIBADecision(s.auditor, ctx, clientID, subjectID, approved)
}

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
		req.SubjectTokenType != TokenTypeJWT &&
		req.SubjectTokenType != TokenTypeIDToken {
		// RFC 8693 §2.1 lists more token types; this server handles signed
		// access tokens + JWTs, plus id_token for the Native SSO 1.0 device-
		// secret exchange (handled in the actor branch below).
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
	// SPIFFE JWT-SVID fallback (cluster C1). Tried ONLY when:
	//   - the local-issuer path above FAILED (so a normal, locally-issued
	//     subject_token_type=jwt token is byte-identical to today — it
	//     validates locally and never reaches here), AND
	//   - the validator is wired (WithSPIFFEJWTSVID; nil ⇒ skipped, so the
	//     feature-off path is byte-identical), AND
	//   - the inbound type is the standard `jwt` type SVIDs use (an
	//     access_token-typed subject_token is never treated as an SVID).
	// The validator further requires the `sub` to be a spiffe:// URI in the
	// configured trust domain, so a foreign non-SVID JWT still fails and
	// collapses to the SAME invalid_grant below. On success the SVID is
	// mapped onto a synthetic claims set the existing issuance path reuses.
	var spiffeID *security.SPIFFEID
	if (err != nil || claims == nil) && s.spiffeValidator != nil && req.SubjectTokenType == TokenTypeJWT {
		if id, verr := s.spiffeValidator.Validate(ctx.Request().Context(), req.SubjectToken, s.spiffeAudience); verr == nil {
			spiffeID = id
			// Build the subject claims from the SVID. The principal is the
			// spiffe:// id; AMR=["spiffe"] tells downstream services this
			// was a mesh-workload authentication (RFC 8176). AuthTime=now
			// because the exchange is the moment the workload presented a
			// valid SVID (an SVID carries no end-user auth event to carry
			// forward). RFC 9068 Subject.ClientID is set later from the
			// exchanging client, exactly as the local-token path does.
			claims = &TokenClaims{
				Subject:  id.URI,
				Extra:    id.Attributes(),
				AuthTime: time.Now(),
				AMR:      []string{core.AMRSpiffe},
			}
			err = nil
		}
	}
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
	// OpenID Connect Native SSO 1.0 §3.2: a device_secret actor takes a
	// dedicated, self-contained path — the secret is not a JWT; it is validated
	// against the device-secret store + the id_token's ds_hash. Requires a wired
	// store (else the feature is off).
	if req.ActorToken != "" && req.ActorTokenType == TokenTypeDeviceSecret {
		if s.deviceSecretStore == nil {
			ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceSecretNotConfigured))
			return
		}
		s.handleDeviceSecretExchange(ctx, claims, req.SubjectToken, req.ActorToken, client, req)
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
			switch {
			case rerr != nil:
				// Store error — default fail-OPEN (continue). Fail-CLOSED
				// (opt-in) treats store-uncertainty AS a replay and
				// rejects with the SAME invalid_grant a detected replay
				// returns, so the wire shape is identical (no oracle).
				if s.jtiReplayFailClosed {
					ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
					return
				}
			case !first:
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
	// Additionally bound the exchanged scope to the DOWNSTREAM client's
	// AllowedScopes (RFC 6749 §3.3) — intersection semantics: the result
	// must be ⊆ subject_token scopes (checked above) AND ⊆ the requesting
	// client's allowlist. Without this an exchange could mint a scope the
	// requesting client is not entitled to merely because the inbound
	// subject_token carried it. The client is authenticated above, so the
	// gate is not a pre-auth probe; empty allowlist = unrestricted (the
	// subject-subset check alone governs, byte-identical to before).
	boundScopes, exScopeErr := oauth.GrantedScopes(scopes, client)
	if exScopeErr != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
		return
	}
	scopes = boundScopes

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

	// Internal audit trail for an accepted SPIFFE JWT-SVID (the
	// security-sensitive inbound-external-identity path). Records WHICH
	// mesh workload (trust domain / ns / sa) was admitted and by which
	// client. SVID REJECTIONS are deliberately NOT audited here — they
	// already collapsed to invalid_grant, and per-cause reject events
	// would re-open the oracle the wire is hardened against (§2).
	if spiffeID != nil && s.auditor != nil {
		evt := &audit.Event{
			Type:     audit.EventSPIFFEJWTSVIDAccepted,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  spiffeID.URI,
			ClientID: client.ID,
			Provider: core.AMRSpiffe,
			ActorIP:  audit.ClientIP(ctx.Request()),
		}
		audit.SetMeta(evt, core.KeySPIFFETrustDomain, spiffeID.TrustDomain)
		if spiffeID.Namespace != "" {
			audit.SetMeta(evt, core.KeySPIFFENamespace, spiffeID.Namespace)
		}
		if spiffeID.ServiceAccount != "" {
			audit.SetMeta(evt, core.KeySPIFFEServiceAccount, spiffeID.ServiceAccount)
		}
		s.auditor.Record(ctx.Request().Context(), evt)
	}

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
//
// handleEndSession delegates to oidc.HandleEndSession — see that
// file for the OIDC RP-Initiated Logout 1.0 flow, including FCL
// iframe gather/render + BCL fan-out + phishing-safe redirect
// allowlist semantics.
func (s *Server) handleEndSession(ctx HandlerContext) { oidc.HandleEndSession(s, ctx) }

// handleRegister delegates to oauth.HandleRegister (RFC 7591 DCR).
func (s *Server) handleRegister(ctx HandlerContext) { oauth.HandleRegister(s, ctx) }

// handleRegistrationGet delegates to oauth.HandleRegistrationGet (RFC 7592 §2.1).
func (s *Server) handleRegistrationGet(ctx HandlerContext) { oauth.HandleRegistrationGet(s, ctx) }

// handleRegistrationPut delegates to oauth.HandleRegistrationPut (RFC 7592 §2.2).
func (s *Server) handleRegistrationPut(ctx HandlerContext) { oauth.HandleRegistrationPut(s, ctx) }

// handleRegistrationDelete delegates to oauth.HandleRegistrationDelete (RFC 7592 §2.3).
func (s *Server) handleRegistrationDelete(ctx HandlerContext) { oauth.HandleRegistrationDelete(s, ctx) }

// mfaResumeState is the JSON-encoded blob persisted alongside the
// spi.MFAChallenge. Opaque to spi.MFAChallengeStore backends; the SSO server
// marshals + unmarshals so the post-step-up handler can replay the
// same finishLogin flow the no-MFA path takes.
//
// CredentialHealth is carried out-of-band from Result on purpose:
// AuthResult.CredentialHealth is json:"-" (kept off all generic
// serialization, including this blob), so the embedded Result would drop
// the signal on the round trip. This is the ONE intentional persistence
// point for the advisory — re-threading it here keeps the post-MFA
// credential-health audit firing exactly as the no-MFA path's does.
type mfaResumeState struct {
	Result           *AuthResult       `json:"result"`
	Request          loginRequest      `json:"request"`
	CredentialHealth *CredentialHealth `json:"credential_health,omitempty"`
}

// issueMFAChallenge mints a single-use challenge ID + persists the
// frozen login state for resumption. Writes the mfa_required response.
// Audit: emits mfa_required (success outcome — primary credential was
// fine, the user just hasn't completed step-up yet).
func (s *Server) issueMFAChallenge(ctx HandlerContext, result *AuthResult, req loginRequest, client *Client) {
	// Set CredentialHealth explicitly: AuthResult.CredentialHealth is
	// json:"-", so the embedded Result drops it; this side channel
	// preserves it for the post-step-up audit in finishLogin.
	stateBlob, err := json.Marshal(&mfaResumeState{Result: result, Request: req, CredentialHealth: result.CredentialHealth})
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
	// Re-attach the advisory carried out-of-band (AuthResult.CredentialHealth
	// is json:"-", so it never survives the embedded Result round trip) so
	// finishLogin emits the credential-health audit on the MFA-resumed path
	// exactly as it does on the direct path.
	state.Result.CredentialHealth = state.CredentialHealth

	// The second factor verified: fold it into the result's amr so the
	// resumed mint carries the real multi-factor signal (RFC 8176, e.g.
	// ["pwd","otp","mfa"]) rather than only the first-factor method
	// captured before the step-up.
	state.Result.AuthMethods = withMFAMethod(state.Result.AuthMethods, req.Method)

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

	// Data-residency write-gate on the SECOND leg. The token is minted NOW, in
	// finishLogin, from the serving region of THIS /auth/mfa request — which
	// went through the same region middleware as /auth/login — so the gate reads
	// the live region here, not the (possibly different) region of the first
	// leg that issued the challenge. Mirrors the credential-path gate exactly
	// (isWrite=true, distinct governance codes, RFC 9207 iss via authzErrorBody,
	// one recordLoginFailure). Without a wired region resolver / residency check
	// the gate never fires (byte-identical). Provider is attributed to the
	// original credential provider, matching the mfa_success audit above.
	if s.residencyGateLogin(ctx, client.ID, state.Result.Provider, client.TenantID) {
		return
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
	// Scope authorization at device-authorization REQUEST time (not at
	// redemption): the client is fully authenticated here and
	// AllowedScopes is in scope, so an unapproved-scope device request is
	// rejected up front in the device flow's own shape — no double-check
	// at /token. The captured DeviceCode.Scopes is the GRANTED set
	// (validated, or defaulted to the client's allowlist when empty), so
	// the eventual token carries its entitled scope.
	scopes, err := oauth.GrantedScopes(splitScope(req.Scope), client)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
		return
	}

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
	if slices.Contains(dc.Scopes, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:     issuedSub,
				Audience:    client.ID,
				Nonce:       dc.Nonce,
				AuthTime:    time.Now(),
				AMR:         []string{dc.Provider},
				Claims:      dc.Attributes,
				AccessToken: token.AccessToken,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, dc.UserID)
			}
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	s.recordSubjectClientAccess(ctx.Request().Context(), dc.UserID, client.ID)
	_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
	ctx.JSON(http.StatusOK, resp)
}

// handleCIBATokenGrant is the client's poll path on /token for
// grant_type=urn:openid:params:grant-type:ciba. Called from the
// GrantCIBA case in handleToken. Mirrors handleDeviceTokenGrant:
//
//   - authorization_pending: user hasn't confirmed out of band yet
//   - slow_down: client polled faster than the issued interval
//   - access_denied: user explicitly denied
//   - expired_token: unknown / expired auth_req_id (oracle-leak
//     collapse — RFC parity with the device flow)
//   - invalid_grant: auth_req_id issued for a different client
//
// or a standard token response on success. AMR/AuthTime are set from
// the approval event per the RFC 9068 access-token claim rules.
func (s *Server) handleCIBATokenGrant(ctx HandlerContext, client *Client, authReqID, dpopJKT, mtlsX5T string) {
	if s.cibaStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrCIBANotConfigured))
		return
	}
	if authReqID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	r, err := s.cibaStore.Get(ctx.Request().Context(), authReqID)
	if err != nil {
		// Unknown / expired / consumed all collapse to expired_token
		// (anti-enumeration — mirrors the device flow's ErrExpiredToken).
		ctx.JSON(http.StatusBadRequest, errorBody(ErrExpiredToken))
		return
	}
	// Bind: an auth_req_id issued for client A can't be polled by client B.
	if r.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// slow_down: poll arrived within the issued interval of the previous
	// poll. Reuses the device-flow anti-thrash logic.
	now := time.Now()
	if !r.LastPoll.IsZero() && r.Interval > 0 && now.Sub(r.LastPoll) < r.Interval {
		_ = s.cibaStore.UpdateLastPoll(ctx.Request().Context(), authReqID, now)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSlowDown))
		return
	}
	_ = s.cibaStore.UpdateLastPoll(ctx.Request().Context(), authReqID, now)

	switch r.Status {
	case oauth.CIBADenied:
		_ = s.cibaStore.Delete(ctx.Request().Context(), authReqID)
		s.recordCIBADecision(ctx, client.ID, r.SubjectID, false)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAccessDenied))
		return
	case oauth.CIBAApproved:
		// fall through to issuance below
	default:
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAuthorizationPending))
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	provider := r.Provider
	if provider == "" {
		provider = CIBAAMR
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, r.SubjectID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                  issuedSub,
		Provider:            provider,
		Resources:           r.Resources,
		ClientID:            client.ID,
		AuthTime:            now,
		AMR:                 []string{provider},
		ACR:                 r.ACRValues,
		TTL:                 client.AccessTokenTTL,
		ConfirmationJKT:     dpopJKT,
		ConfirmationX5TS256: mtlsX5T,
	}, r.Scopes)
	if err != nil {
		s.logger.Error("ciba token issuance failed", "strategy", strategy, "error", err)
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
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			r.SubjectID, client.ID, provider, r.Scopes, nil, r.Nonce, r.Resources, nil, "", client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, r.SubjectID, false)
		}
	}
	if slices.Contains(r.Scopes, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:     issuedSub,
				Audience:    client.ID,
				Nonce:       r.Nonce,
				AuthTime:    now,
				AMR:         []string{provider},
				AccessToken: token.AccessToken,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err)
			} else {
				resp[KeyIDToken] = idToken
				s.recordIDTokenIssued(ctx, client.ID, r.SubjectID)
			}
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, r.SubjectID)
	s.recordSubjectClientAccess(ctx.Request().Context(), r.SubjectID, client.ID)
	s.recordCIBADecision(ctx, client.ID, r.SubjectID, true)
	// Single-use: delete after minting so a replay hits expired_token.
	_ = s.cibaStore.Delete(ctx.Request().Context(), authReqID)
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
	s.recordTenantLoginAttempt(ctx, clientID, "failure")
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
	s.recordTenantLoginAttempt(ctx, clientID, "success")
	s.recordTenantTokenIssued(ctx, clientID, strategy)
	s.observeLoginDuration(ctx, provider, "success")
	s.dispatchLoginAnomaly(ctx, userID, clientID, provider, "success", "")
	if s.auditor == nil {
		return
	}
	audit.RecordLoginSuccess(s.auditor, ctx, clientID, provider, strategy, userID, sessionID)
}

// recordCredentialHealth emits a non-blocking credential-health signal
// after a successful login (password_weak / password_compromised). It is
// purely informational — the login already succeeded and was not blocked.
// nil health short-circuits with zero overhead (no checker wired, or a
// healthy credential). Counts the signal toward the bounded
// credential-health metric before auditing.
func (s *Server) recordCredentialHealth(ctx HandlerContext, clientID, userID string, health *CredentialHealth) {
	if health == nil {
		return
	}
	if s.metrics != nil {
		signal := metrics.SignalWeak
		if health.Compromised {
			signal = metrics.SignalCompromised
		}
		s.metrics.CredentialHealthSignalsTotal.WithLabelValues(signal).Inc()
	}
	audit.RecordCredentialHealth(s.auditor, ctx, clientID, userID, health)
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
	s.recordTenantTokenIssued(ctx, clientID, strategy)
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

// recordRefreshRotationVelocity emits a refresh_rotation_velocity_exceeded
// event after the per-family rotation-velocity cap trips and the family is
// killed. The wire response stays the generic invalid_grant — this audit
// event (plus sso_refresh_rotation_velocity_exceeded_total) is the only
// place the velocity detail surfaces.
func (s *Server) recordRefreshRotationVelocity(ctx HandlerContext, clientID, familyID string, count, killed int) {
	audit.RecordRefreshRotationVelocityExceeded(s.auditor, ctx, clientID, familyID, count, killed)
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

	// JARM (JWT Secured Authorization Response Mode) — JWS algs the AS
	// uses to sign the authorization response JWT. Omitted unless a
	// JARM signer is wired (WithJARM); its presence signals JARM
	// support alongside the jwt response_modes.
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

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

	// OIDC Core §3 response-encryption metadata. Populated only when
	// WithJWEResponseEncrypter is wired (the response-direction mirror
	// of the request_object_encryption_* fields above) — the encrypter's
	// SupportedAlgs() / SupportedEncs() surface here so RPs know which
	// alg + enc to register for id_token / userinfo encryption. Omitted
	// (fields disappear from the JSON) when no encrypter is wired;
	// clients that nonetheless register an encrypted_response_alg get a
	// fail-closed response.
	IDTokenEncryptionAlgValuesSupported  []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported  []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

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

	// OIDC CIBA Core 1.0 discovery metadata. Advertised only when
	// WithCIBA is wired (opt-in). BackchannelAuthenticationEndpoint
	// points at /backchannel-authentication;
	// BackchannelTokenDeliveryModesSupported is ["poll"], plus "ping"
	// when a CIBAPingNotifier is wired (WithCIBAPingNotifier); push
	// delivery is not implemented.
	// BackchannelUserCodeParameterSupported is false (the user is
	// resolved via login_hint/id_token_hint, not a user_code).
	BackchannelAuthenticationEndpoint      string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelUserCodeParameterSupported  bool     `json:"backchannel_user_code_parameter_supported,omitempty"`
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
	cfg := s.buildOIDCConfiguration(ctx, base)

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

// buildOIDCConfiguration assembles the fully-finalized OpenID Connect
// Discovery 1.0 + RFC 8414 metadata struct for the given request base URL
// — every derived field plus the RFC 8414 §2.1 signed_metadata. Extracted
// from handleOIDCDiscovery (behavior-preserving) so the federation entity
// configuration can DERIVE its openid_provider metadata from the SAME
// projection (see BuildOPMetadata) instead of hand-duplicating the
// derivation, which would risk the two metadata views drifting apart. The
// output is byte-identical to the previous inline assembly — the existing
// discovery + signed_metadata tests are the proof.
func (s *Server) buildOIDCConfiguration(ctx HandlerContext, base string) oidcConfiguration {
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
		RequestParameterSupported:    true,
		RequestURIParameterSupported: false,
		// JAR request objects (RFC 9101) verify through
		// security.VerifyCompactJWS, which accepts the full asymmetric
		// allowlist — advertise exactly what is accepted on the wire so
		// RP metadata validation reflects reality.
		RequestObjectSigningAlgValuesSupported: security.AsymmetricJWSAlgValues(),
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
	if s.jweResponseEncrypter != nil {
		// Response-direction JWE: advertise the alg + enc the AS can
		// produce so RPs register a matching id_token / userinfo
		// encrypted_response_alg + _enc (and publish a use:enc JWKS key).
		algs := s.jweResponseEncrypter.SupportedAlgs()
		encs := s.jweResponseEncrypter.SupportedEncs()
		cfg.IDTokenEncryptionAlgValuesSupported = algs
		cfg.IDTokenEncryptionEncValuesSupported = encs
		cfg.UserinfoEncryptionAlgValuesSupported = algs
		cfg.UserinfoEncryptionEncValuesSupported = encs
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
	// Signing algs are derived from the wired signers (EdDSA for an
	// Ed25519JWTIssuer, ES256 for an ECDSAJWTIssuer, both in a mixed
	// deployment) or pinned by WithSupportedSigningAlgs. See
	// (*Server).SigningAlgValues.
	signingAlgs := s.SigningAlgValues(ctx.Request().Context())
	if s.idTokenIssuer != nil {
		cfg.IDTokenSigningAlgValuesSupported = signingAlgs
		// Userinfo signing capability is gated on the issuer
		// implementing the oidc.UserinfoSigner extension. The default
		// Ed25519JWTIssuer does — third-party implementations may
		// not, and the omitempty serialization correctly hides the
		// claim in that case.
		if _, ok := s.idTokenIssuer.(oidc.UserinfoSigner); ok {
			cfg.UserinfoSigningAlgValuesSupported = signingAlgs
		}
	}
	if s.cibaStore != nil {
		// OIDC CIBA Core 1.0 §4: advertise the backchannel endpoint +
		// delivery modes only when CIBA is wired (opt-in). Poll is always
		// available; ping is added when a CIBAPingNotifier is wired
		// (WithCIBAPingNotifier). Push delivery is not implemented. Poll
		// mode resolves the user from login_hint/id_token_hint rather than
		// a user_code, so the user_code parameter is unsupported.
		cfg.BackchannelAuthenticationEndpoint = base + PathBackchannelAuth
		modes := []string{"poll"}
		if s.cibaPingNotifier != nil {
			modes = append(modes, "ping")
		}
		cfg.BackchannelTokenDeliveryModesSupported = modes
		cfg.BackchannelUserCodeParameterSupported = false
		cfg.GrantTypesSupported = append(cfg.GrantTypesSupported, GrantCIBA)
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
	// no opt-in store to wire. DPoP proofs verify through
	// security.VerifyCompactJWS, so advertise the full asymmetric
	// allowlist (DPoP clients are almost always ES256).
	cfg.DPoPSigningAlgValuesSupported = security.AsymmetricJWSAlgValues()
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
	// private_key_jwt (RFC 7523) client assertions verify through
	// security.VerifyCompactJWS on every endpoint that accepts them, so
	// the advertised signing-alg lists are the full asymmetric allowlist
	// (was EdDSA-only) — RPs overwhelmingly hold RS256/ES256 keys.
	authAlgs := security.AsymmetricJWSAlgValues()
	cfg.TokenEndpointAuthSigningAlgValuesSupported = authAlgs
	cfg.IntrospectionEndpointAuthSigningAlgValuesSupported = authAlgs
	cfg.RevocationEndpointAuthSigningAlgValuesSupported = authAlgs
	if s.parStore != nil {
		cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported = authAlgs
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

	// JARM — advertise the jwt response modes + the signing alg only
	// when a JARM signer is wired (WithJARM). EdDSA is the alg the
	// default Ed25519 signer uses.
	if s.jarmSigner != nil {
		cfg.ResponseModesSupported = append(cfg.ResponseModesSupported,
			oidc.ResponseModeJWT, oidc.ResponseModeQueryJWT,
			oidc.ResponseModeFragmentJWT, oidc.ResponseModeFormPostJWT,
		)
		// JARM responses are signed with the server's signing key, so
		// advertise the actual signing alg(s) (EdDSA / ES256 / RS256 /
		// PS256), not a hardcoded EdDSA.
		cfg.AuthorizationSigningAlgValuesSupported = s.SigningAlgValues(ctx.Request().Context())
	}

	// FAPI 2.0 enforce mode: the profile makes these constraints
	// server-wide and unconditional, so the discovery doc MUST advertise
	// them as required (RP metadata validation then reflects reality).
	// Inspection mode deliberately leaves discovery unchanged — it only
	// audits, so advertising hard requirements there would mislead RPs.
	if s.fapiValidator.Enforcing() {
		cfg.RequirePushedAuthReq = true
		cfg.RequireSignedRequestObjectGlobal = true
		cfg.ResponseTypesSupported = []string{"code"}
		cfg.CodeChallengeMethodsSupported = []string{PKCEMethodS256}
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

	return cfg
}

// BuildOPMetadata projects the openid_provider metadata for the OpenID
// Federation 1.0 entity configuration (federation.Deps). It DERIVES from the
// same buildOIDCConfiguration projection the /.well-known/openid-configuration
// discovery doc uses — taking only the federation-relevant subset (OpenID
// Federation 1.0 §4.5: federation OP metadata is OIDC OP metadata) — so the
// federation view can never drift from the discovery view. signed_metadata
// (an RFC 8414 field of the discovery doc) is deliberately NOT carried: the
// Entity Statement is itself a signed JWS, so the discovery-doc signature is
// redundant inside it.
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
//
// fpValid/fpCount/fpHash carry the cheap client-set fingerprint
// (core.ClientStoreStats) captured when this snapshot's derived fields
// were last computed from a full List. On a would-be cache miss the
// refresh path re-reads the fingerprint and, when it still matches,
// reuses the derived fields verbatim instead of re-Listing every
// client — see discoverySnapshot. fpValid is false when the store
// doesn't implement ClientStoreStats or the Stats call failed, which
// forces the legacy full-List recompute.
type clientDiscoverySnapshot struct {
	requirePAR                 bool
	requireSignedRequestObject bool
	frontchannelLogout         bool
	scopes                     []string
	authorizationDetailTypes   []string
	expiresAt                  time.Time

	fpValid bool
	fpCount int
	fpHash  string
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
	// Stale-but-present snapshot: before paying for a full List +
	// re-projection, ask the store for a cheap fingerprint. If the
	// client set hasn't changed in any discovery-relevant way, reuse
	// the prior snapshot's derived fields and just extend the TTL.
	if prev := s.discoveryCache.Load(); prev != nil && prev.fpValid {
		if snap := s.refreshIfUnchanged(ctx, prev); snap != nil {
			s.discoveryCache.Store(snap)
			return snap
		}
	}
	snap := s.computeDiscoverySnapshot(ctx)
	s.discoveryCache.Store(snap)
	return snap
}

// refreshIfUnchanged returns a TTL-extended copy of prev when the
// client store exposes a cheap fingerprint (core.ClientStoreStats) that
// still matches prev's. The returned snapshot shares prev's derived
// fields verbatim — they were computed from the same client set and the
// slices are immutable after publication, so sharing is race-free. It
// returns nil to signal "fingerprint changed, unavailable, or
// unsupported — fall back to a full recompute".
func (s *Server) refreshIfUnchanged(ctx context.Context, prev *clientDiscoverySnapshot) *clientDiscoverySnapshot {
	stats, ok := s.clientStore.(core.ClientStoreStats)
	if !ok {
		return nil
	}
	count, hash, err := stats.Stats(ctx)
	if err != nil {
		// Treat a Stats outage like the degraded-discovery path: don't
		// trust a possibly-partial fingerprint, force a recompute (which
		// itself degrades gracefully when List fails).
		return nil
	}
	if count != prev.fpCount || hash != prev.fpHash {
		return nil
	}
	refreshed := *prev
	refreshed.expiresAt = time.Now().Add(s.discoveryCacheTTL)
	return &refreshed
}

// computeDiscoverySnapshot does the expensive client-store iteration
// once and projects all four derived fields. Splitting compute from
// the cache wrapper lets tests assert the projection directly
// without poking the cache.
//
// When the store exposes a cheap fingerprint (core.ClientStoreStats),
// the snapshot is stamped with that fingerprint computed from the SAME
// clients we just Listed (no second store round-trip). The stamp must
// match what Stats() would independently return for this set, so the
// next miss can compare cheaply and skip the recompute — see
// refreshIfUnchanged. core.ClientSetFingerprint reads only the
// discovery-relevant fields, so a backend whose schema omits some of
// them (sqlite) digests List() and Stats() identically (both zero).
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
	// Stamp the fingerprint only when the cache is live (ttl > 0): with
	// caching disabled the snapshot is discarded immediately, so the
	// digest would be pure waste on every request.
	if s.discoveryCacheTTL > 0 {
		if _, ok := s.clientStore.(core.ClientStoreStats); ok {
			snap.fpValid = true
			snap.fpCount = len(clients)
			snap.fpHash = core.ClientSetFingerprint(clients)
		}
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

// invalidateDiscoveryCaches drops both the derived discovery snapshot
// and every cached rendered document, so the next request recomputes
// from current client state. Local-only; never publishes (the bus
// subscriber calls this directly, and InvalidateDiscoveryCache is the
// publishing entry point).
func (s *Server) invalidateDiscoveryCaches() {
	s.discoveryCache.Store(nil)
	s.discoveryDocCache.Range(func(k, _ any) bool {
		s.discoveryDocCache.Delete(k)
		return true
	})
}

// InvalidateDiscoveryCache clears this replica's discovery snapshot +
// rendered-document caches and, when an invalidation bus is wired,
// publishes a reload so every other replica does the same. Wire this
// into admin handlers that mutate discovery-affecting client state
// (scopes, registration) so a config change converges across the
// cluster immediately rather than after each node's discovery cache
// TTL. Safe to call unconditionally; publish failures are logged, not
// propagated (peers fall back to their TTL).
func (s *Server) InvalidateDiscoveryCache() {
	s.invalidateDiscoveryCaches()
	s.InvalidateJWKSBodyCache()
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindDiscoveryReload}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "error", err)
		}
	}
}

// writeDiscoveryDoc delegates to oidc.WriteDoc with the server's
// configured cache TTL.
func (s *Server) writeDiscoveryDoc(ctx HandlerContext, entry *discoveryDocEntry) {
	oidc.WriteDoc(ctx, entry, s.discoveryDocCacheTTL)
}

// InvalidateAuthzPolicyBundleCache clears this replica's cached
// authorization policy bundle for clientID and, when an invalidation bus
// is wired, publishes a KindAuthzPolicyChange so every other replica does
// the same — closing the cross-replica window where a sidecar could pull
// a stale role-definition bundle from another node until that node's TTL
// elapses. Wire this into the admin role/menu mutation handlers (gRPC
// PermissionAdminService) via a callback so a role change converges before
// the bundle cache TTL.
//
// Safe to call unconditionally. Publish failures are logged, not
// propagated: the local invalidation already succeeded and peers fall back
// to their TTL, so a mutation must never fail because the bus is down
// (fail-open on publish, AGENTS.md §2).
func (s *Server) InvalidateAuthzPolicyBundleCache(clientID string) {
	s.invalidateAuthzPolicyBundleCacheLocal(clientID)
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindAuthzPolicyChange, Key: clientID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", clientID, "error", err)
		}
	}
}

// WithDiscoveryDocCacheTTL configures how long a rendered discovery
// document body may serve from cache. ttl <= 0 disables body caching
// (snapshot caching via [WithDiscoveryCacheTTL] continues independently).
// Default is [DefaultDiscoveryDocCacheTTL].
func WithDiscoveryDocCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.discoveryDocCacheTTL = ttl }
}

// DefaultAuthzPolicyBundleCacheTTL bounds how long a rendered
// authorization policy bundle may serve from this replica's body cache
// before it re-renders from the permissions provider. Role definitions
// change rarely and admin mutations invalidate the cache immediately
// (locally + cluster-wide via the bus), so this is just the backstop
// freshness window for a missed invalidation — set generously (minutes,
// not seconds) since a sidecar polls the bundle, not the hot request path.
const DefaultAuthzPolicyBundleCacheTTL = 5 * time.Minute

// WithAuthzPolicyBundleCacheTTL configures how long a rendered
// authorization policy bundle body may serve from cache. ttl <= 0
// disables body caching AND the response-side ETag / Cache-Control
// headers (every pull renders fresh, downstream caches told not to
// cache) — matching the discovery-doc cache contract. Default is
// [DefaultAuthzPolicyBundleCacheTTL].
func WithAuthzPolicyBundleCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.authzPolicyBundleCacheTTL = ttl }
}

// authzPolicyBundleCacheKey namespaces a cached bundle by (clientID,
// baseURL). The NUL byte can't appear in either component, so it is an
// unambiguous separator (no client_id/base-url pair can collide).
func authzPolicyBundleCacheKey(clientID, base string) string {
	return clientID + "\x00" + base
}

// lookupAuthzPolicyBundleCache returns a fresh cached entry for the
// (clientID, base) pair, or nil to signal "render fresh". Mirrors
// lookupDiscoveryDocCache: lock-free read, stale entries are dropped.
func (s *Server) lookupAuthzPolicyBundleCache(clientID, base string) *discoveryDocEntry {
	v, ok := s.authzPolicyBundleCache.Load(authzPolicyBundleCacheKey(clientID, base))
	if !ok {
		return nil
	}
	entry, _ := v.(*discoveryDocEntry)
	if entry.Fresh() {
		return entry
	}
	s.authzPolicyBundleCache.Delete(authzPolicyBundleCacheKey(clientID, base))
	return nil
}

func (s *Server) storeAuthzPolicyBundleCache(clientID, base string, entry *discoveryDocEntry) {
	s.authzPolicyBundleCache.Store(authzPolicyBundleCacheKey(clientID, base), entry)
}

// invalidateAuthzPolicyBundleCacheLocal drops every cached bundle render
// for clientID across all base URLs (a multi-host deployment caches one
// entry per host). Local-only; the publishing entry point is
// InvalidateAuthzPolicyBundleCache. The key is "<clientID>\x00<base>", so
// a prefix match on "<clientID>\x00" scopes the sweep to one client.
func (s *Server) invalidateAuthzPolicyBundleCacheLocal(clientID string) {
	prefix := clientID + "\x00"
	s.authzPolicyBundleCache.Range(func(k, _ any) bool {
		if ks, ok := k.(string); ok && strings.HasPrefix(ks, prefix) {
			s.authzPolicyBundleCache.Delete(k)
		}
		return true
	})
}

// handleAuthzPolicyBundle serves the read-only role-DEFINITION export a
// service-mesh sidecar pulls to enforce authorization locally (no
// per-request Authorizer RPC). Admin-gated (admin:read) by the path
// prefix /api/v1/admin/ — see admin.IsProtectedPath.
//
// Unlike credential endpoints this is a CACHEABLE read: it stamps the
// public Cache-Control + strong ETag exactly like the discovery doc (via
// oidc.WriteDoc), NOT no-store. The ETag is content-based (sha256 over the
// bundle's canonical role bytes, EXCLUDING generated_at), so the same role
// set yields the same ETag across regenerations and a sidecar's
// If-None-Match short-circuits to 304.
//
// Error shape mirrors the admin client read (handleGetClient): missing
// client_id -> 400 missing_client_id; unknown client -> 404
// client_not_found (revealing existence to an authenticated admin is
// fine). Reuses the existing wire error vocabulary — no new error code.
func (s *Server) handleAuthzPolicyBundle(ctx HandlerContext) {
	if s.permissions == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	clientID := ctx.Request().URL.Query().Get(core.KeyClientID)
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}
	// 404 on an unknown client so an enumeration of role definitions can't
	// target a non-existent app — and so the response matches the admin
	// CRUD 404 pattern. Skipped when no client store is wired (the bundle
	// is still derivable purely from the permissions provider).
	if s.clientStore != nil {
		if _, err := s.clientStore.Get(ctx.Request().Context(), clientID); err != nil {
			ctx.JSON(http.StatusNotFound, errorBody(ErrClientNotFound))
			return
		}
	}

	base := requestBaseURL(ctx.Request())
	if s.authzPolicyBundleCacheTTL > 0 {
		if entry := s.lookupAuthzPolicyBundleCache(clientID, base); entry != nil {
			oidc.WriteDoc(ctx, entry, s.authzPolicyBundleCacheTTL)
			return
		}
	}

	bundle, err := permissions.BuildPolicyBundle(ctx.Request().Context(), s.permissions, clientID)
	if err != nil {
		s.logger.Error("authz policy bundle build failed", "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// ttl <= 0 disables both the in-process cache AND the ETag /
	// Cache-Control headers — every pull renders fresh.
	if s.authzPolicyBundleCacheTTL <= 0 {
		ctx.JSON(http.StatusOK, bundle)
		return
	}
	body, err := json.Marshal(bundle)
	if err != nil {
		s.logger.Error("authz policy bundle marshal failed", "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	// ETag is hashed over the bundle's CANONICAL bytes (role content,
	// EXCLUDING generated_at), not the marshaled body — so a re-render
	// with unchanged roles keeps the same ETag and 304s. The cache entry
	// carries the JSON body for the 200 path and that stable ETag for the
	// If-None-Match path.
	canon := oidc.BuildDocEntry(bundle.CanonicalBytes(), s.authzPolicyBundleCacheTTL)
	entry := &discoveryDocEntry{Body: body, ETag: canon.ETag, ExpiresAt: canon.ExpiresAt}
	s.storeAuthzPolicyBundleCache(clientID, base, entry)
	oidc.WriteDoc(ctx, entry, s.authzPolicyBundleCacheTTL)
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

// isValidResponseMode reports whether mode is acceptable on this
// server. The plain modes (query / fragment / form_post) are always
// valid; the JARM modes (jwt / query.jwt / fragment.jwt /
// form_post.jwt) are valid only when a JARM signer is wired — without
// one they fail closed (invalid_request) rather than silently
// degrading to an unsigned response.
func (s *Server) isValidResponseMode(mode string) bool {
	if oidc.IsValidResponseMode(mode) {
		return true
	}
	return s.jarmSigner != nil && oidc.IsJARMResponseMode(mode)
}

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

// AuthenticatedSubject exposes authenticatedSubject for handlers/ subpackages
// (Deps interface needs it as an exported method).
func (s *Server) AuthenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	return s.authenticatedSubject(ctx)
}

// Audit handlers (delegators — bodies in audit/handlers.go).
func (s *Server) handleAuditEvents(ctx HandlerContext)    { audit.HandleEvents(s, ctx) }
func (s *Server) handleAuditEventByID(ctx HandlerContext) { audit.HandleEventByID(s, ctx) }
func (s *Server) handleAuditFacets(ctx HandlerContext)    { audit.HandleFacets(s, ctx) }

// JWKS handler (delegator — body in oidc/handlers.go).
func (s *Server) handleJWKS(ctx HandlerContext) { oidc.HandleJWKS(s, ctx) }

// handleTenantUsage serves GET /api/v1/admin/tenants/:id/usage.
// Admin-gated (admin:read) by the /api/v1/admin/ prefix.
//
// Query parameters:
//
//	period=day|month   (default: day)
//	start=YYYY-MM-DD   (default: today UTC)
func (s *Server) handleTenantUsage(ctx HandlerContext) {
	tenantID := ctx.Param("id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}

	period := metering.UsagePeriod(ctx.Request().URL.Query().Get("period"))
	if period == "" {
		period = metering.PeriodDay
	}
	if period != metering.PeriodDay && period != metering.PeriodMonth {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}

	startStr := ctx.Request().URL.Query().Get("start")
	var start time.Time
	if startStr == "" {
		start = time.Now().UTC()
	} else {
		var err error
		start, err = time.ParseInLocation("2006-01-02", startStr, time.UTC)
		if err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
			return
		}
	}

	u, err := s.usageAggregator.Usage(ctx.Request().Context(), tenantID, period, start)
	if err != nil {
		s.logger.Error("tenant usage aggregation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, u)
}

// handleAdminListUserConsents serves GET /api/v1/admin/users/:id/consents — an
// operator/helpdesk views which apps a user has authorized. admin:read (gated
// by AdminMiddleware via the /api/v1/admin/ prefix).
func (s *Server) handleAdminListUserConsents(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	grants, err := s.consentStore.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list consents failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if grants == nil {
		grants = []core.ConsentGrant{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"consents": grants})
}

// handleAdminRevokeUserConsent serves DELETE /api/v1/admin/users/:id/consents/:client_id
// — revoke a user's grant for an app on their behalf. admin:write. A missing
// grant is a 404 so the caller knows it wasn't there; emits admin_consent_revoked.
func (s *Server) handleAdminRevokeUserConsent(ctx HandlerContext) {
	userID := ctx.Param("id")
	clientID := ctx.Param("client_id")
	if userID == "" || clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if _, err := s.consentStore.GetConsent(ctx.Request().Context(), userID, clientID); err != nil {
		if errors.Is(err, core.ErrNoConsentGrant) {
			ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
			return
		}
		s.logger.Error("admin get consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.consentStore.RevokeConsent(ctx.Request().Context(), userID, clientID); err != nil {
		s.logger.Error("admin revoke consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminConsentRevoked, userID, KeyClientID, clientID)
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminListUserMFA serves GET /api/v1/admin/users/:id/mfa — an
// operator/helpdesk views a user's registered second factors. admin:read.
func (s *Server) handleAdminListUserMFA(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if factors == nil {
		factors = []core.MFAEnrolledFactor{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"factors": factors})
}

// handleAdminRemoveUserMFA serves DELETE /api/v1/admin/users/:id/mfa/:factor_id
// — unbind a user's second factor on their behalf (helpdesk "lost phone, reset
// MFA"). admin:write. A factor the user doesn't have is a 404 (ownership is
// enforced via the user-scoped list, same as the self-service path); emits
// admin_mfa_factor_removed.
func (s *Server) handleAdminRemoveUserMFA(ctx HandlerContext) {
	userID := ctx.Param("id")
	factorID := ctx.Param("factor_id")
	if userID == "" || factorID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(factors, func(f core.MFAEnrolledFactor) bool { return f.ID == factorID }) {
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if err := s.mfaEnrollmentStore.RemoveFactor(ctx.Request().Context(), userID, factorID); err != nil {
		s.logger.Error("admin remove mfa factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminMFAFactorRemoved, userID, "factor_id", factorID)
	ctx.JSON(http.StatusNoContent, nil)
}

// recordAdminUserAction emits an admin_* audit event for a helpdesk action on a
// user's self-service state. ActorID is the acting ADMIN (from the
// AdminMiddleware-stamped context); the target user + the affected
// client_id/factor_id ride in metadata.
func (s *Server) recordAdminUserAction(ctx HandlerContext, evtType audit.EventType, targetUser, metaKey, metaVal string) {
	if s.auditor == nil {
		return
	}
	actor, _, _ := AdminActorFromContext(ctx.Request().Context())
	evt := &audit.Event{
		Type:    evtType,
		Outcome: audit.OutcomeSuccess,
		ActorID: actor,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "target_user", targetUser)
	if metaKey != "" {
		audit.SetMeta(evt, metaKey, metaVal)
	}
	s.auditor.Record(ctx.Request().Context(), evt)
}

// handleAdminResetUserPassword serves POST /api/v1/admin/users/:id/password —
// a helpdesk/admin sets a user's password on their behalf. admin:write. Body:
// {new_password}. Emits admin_password_reset (never the password). The new
// password takes effect on the user's next login (the same credential the
// self-service /me/password change writes).
func (s *Server) handleAdminResetUserPassword(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.NewPassword == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.passwordCredentialStore.SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		s.logger.Error("admin set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminPasswordReset, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminSetUserEmail serves POST /api/v1/admin/users/:id/email — a
// helpdesk/admin force-sets a user's email on their behalf (onboarding-typo
// correction, domain migration), bypassing the user-facing verified
// email-change flow (which requires the user to control the new address).
// admin:write. Body: {email}. A missing user is a 404. Emits
// admin_user_email_changed (never the email value — it's PII).
func (s *Server) handleAdminSetUserEmail(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	u, err := s.userProvider.GetByID(ctx.Request().Context(), userID)
	if err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	u.Email = strings.TrimSpace(req.Email)
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), u); err != nil {
		s.logger.Error("admin set email failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminUserEmailChanged, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminClearAccountLockout serves POST /api/v1/admin/account-lockout/clear
// — a helpdesk clears a brute-force lockout so a legitimately-locked user can
// retry immediately, without waiting out the auto-unlock duration. admin:write.
// Body: {client_id, identifier}. The lockout is keyed on
// <client_id>:<identifier> (the credential the user authenticates with), NOT the
// userID, so both are required. Reuses RegisterSuccess, which the AccountLockout
// contract defines as resetting the failure counter AND any active lock for the
// key — so this is idempotent (clearing a non-locked key succeeds). Emits
// admin_account_unlocked.
func (s *Server) handleAdminClearAccountLockout(ctx HandlerContext) {
	var req struct {
		ClientID   string `json:"client_id"`
		Identifier string `json:"identifier"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.ClientID == "" || req.Identifier == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	// Build the same key the login path uses (security.LockoutKey →
	// "<client_id>:<identifier>"). The field name is immaterial — the key format
	// is identical regardless of which credential field locked the account.
	key := security.LockoutKey(req.ClientID, map[string]string{"username": req.Identifier})
	if err := s.accountLockout.RegisterSuccess(ctx.Request().Context(), key); err != nil {
		s.logger.Error("admin clear lockout failed", "client_id", req.ClientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminAccountUnlocked, req.Identifier, KeyClientID, req.ClientID)
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminRevokeUserDeviceSecrets serves DELETE /api/v1/admin/users/:id/device-secrets
// — revoke all of a user's Native SSO device-secret bindings (lost/compromised
// device lockout). admin:write. 501 when the wired DeviceSecretStore can't
// revoke by subject; emits admin_device_secrets_revoked with the count.
func (s *Server) handleAdminRevokeUserDeviceSecrets(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := s.deviceSecretStore.(core.DeviceSecretRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeBySubject(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin revoke device secrets failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminDeviceSecretsRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// handleAdminRevokeUserPasswordResetTokens serves
// DELETE /api/v1/admin/users/:id/password-reset-tokens — invalidate every
// pending forgot-password token for a user (wrong-address / leak / lost-channel
// recovery). admin:write. 501 when the wired PasswordResetStore can't revoke by
// user; emits admin_password_reset_tokens_revoked with the count. Idempotent.
func (s *Server) handleAdminRevokeUserPasswordResetTokens(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := s.passwordResetStore.(core.PasswordResetRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin revoke password reset tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminPasswordResetTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// handleAdminRevokeUserEmailChangeTokens serves
// DELETE /api/v1/admin/users/:id/email-change-tokens — invalidate every pending
// email-change verification token for a user (wrong-address / ownership-dispute
// recovery). admin:write. 501 when the wired EmailChangeStore can't revoke by
// user; emits admin_email_change_tokens_revoked with the count. Idempotent.
func (s *Server) handleAdminRevokeUserEmailChangeTokens(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := s.emailChangeStore.(core.EmailChangeRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin revoke email change tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminEmailChangeTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// meSubjectOrChallenge extracts the bearer subject for /sessions/me and
// /consents/me. Unlike authenticatedSubject, it stamps the RFC 6750 §3
// WWW-Authenticate challenge header BEFORE writing the 401 body, so these
// credential-adjacent endpoints conform to the same challenge contract as
// /userinfo. Returns (userID, true) on success; (_, false) when the 401 has
// already been written.
func (s *Server) meSubjectOrChallenge(ctx HandlerContext) (userID string, ok bool) {
	claims, ok := s.meClaimsOrChallenge(ctx)
	if !ok {
		return "", false
	}
	return claims.Subject, true
}

// meClaimsOrChallenge is the full-claims variant backing meSubjectOrChallenge:
// it validates the bearer and returns the whole TokenClaims so handlers that
// need more than the subject (e.g. the current session SID for "sign out of
// other devices") can read it without a second validation. On any failure it
// has already written the oracle-safe resource challenge + 401.
func (s *Server) meClaimsOrChallenge(ctx HandlerContext) (*core.TokenClaims, bool) {
	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return nil, false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		s.setResourceBearerChallenge(ctx, s.resolveIssuer(ctx), ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return nil, false
	}
	return claims, true
}

// handleBranding serves GET /branding — the public white-label lookup the
// hosted login SPA fetches before authentication to theme the sign-in page.
// Branding is per-vanity-host (tenant.Domain.Branding), so it resolves by the
// request Host, reusing the exact host extraction + trust model the tenant
// middleware uses. Returns only that presentation map (name, color, logo).
//
// Unauthenticated and non-enumerable: an unknown host, a domain with no
// branding, no tenant store, or a store outage all return the same 200 with an
// empty branding object, so the endpoint never reveals which hosts are
// configured. Branding carries only non-sensitive UI data.
func (s *Server) handleBranding(ctx HandlerContext) {
	out := map[string]any{
		"branding": map[string]string{},
		KeyIss:     s.resolveIssuer(ctx),
	}
	if s.tenantStore == nil {
		ctx.JSON(http.StatusOK, out)
		return
	}
	// Prefer the domain the tenant middleware already resolved for this host.
	if r, ok := tenant.FromHandlerContext(ctx); ok && r.Domain != nil && len(r.Domain.Branding) > 0 {
		out["branding"] = r.Domain.Branding
		ctx.JSON(http.StatusOK, out)
		return
	}
	// Fall back to a direct host lookup — the middleware skips stashing for a
	// suspended tenant. Branding is UI-only, so showing a suspended tenant's
	// brand on its own login host is harmless. Use the same host extractor the
	// tenant middleware was configured with, so an operator who disabled
	// X-Forwarded-Host trust is honored here too.
	extract := s.tenantMiddlewareOpts.HostExtractor
	if extract == nil {
		extract = tenant.DefaultHostExtractor
	}
	host := extract(ctx.Request())
	if host == "" {
		ctx.JSON(http.StatusOK, out)
		return
	}
	d, err := s.tenantStore.GetDomain(ctx.Request().Context(), host)
	if err != nil || d == nil || len(d.Branding) == 0 {
		ctx.JSON(http.StatusOK, out)
		return
	}
	out["branding"] = d.Branding
	ctx.JSON(http.StatusOK, out)
}

// handleMe serves GET /me — the authenticated user's self-service account
// overview: their own profile plus active-session and granted-app counts. The
// landing entry for a self-service portal, consolidating data the SPA would
// otherwise assemble from /sessions/me + /consents/me + the token.
//
// Credential-adjacent (same no-store headers as /userinfo). Each enrichment is
// best-effort: a store outage drops that field rather than failing the whole
// response, and the sub/iss baseline is always present.
func (s *Server) handleMe(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	out := map[string]any{
		KeyIss: s.resolveIssuer(ctx),
		KeySub: userID,
	}
	if s.userProvider != nil {
		if u, err := s.userProvider.GetByID(ctx.Request().Context(), userID); err == nil && u != nil {
			out["user"] = u
		}
	}
	if s.sessionMgr != nil {
		if sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID); err == nil {
			out["active_sessions"] = len(sessions)
		}
	}
	if s.consentStore != nil {
		if grants, err := s.consentStore.ListByUser(ctx.Request().Context(), userID); err == nil {
			out["granted_apps"] = len(grants)
		}
	}
	ctx.JSON(http.StatusOK, out)
}

// handlePatchMe serves PATCH /me — the authenticated user edits their own
// profile. Body: {name?, attributes?}. The display name is always editable (an
// empty/omitted name leaves it unchanged); attributes are applied ONLY for
// keys in the operator's self-editable allowlist (WithSelfEditableProfileAttributes)
// — every other key is silently dropped, so a user can never escalate by
// writing an authz-relevant attribute the operator keeps alongside presentation
// data. Identity-critical fields (id, external_id, provider, email, timestamps)
// are never self-editable: email in particular needs a verification flow that
// lives outside self-service. Credential-adjacent: no-store headers.
func (s *Server) handlePatchMe(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		Name       string            `json:"name"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	u, err := s.userProvider.GetByID(ctx.Request().Context(), userID)
	if err != nil || u == nil {
		// The caller authenticated, so their record should exist; collapse a
		// lookup miss/outage into 404 rather than leak store internals.
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	if len(req.Attributes) > 0 && len(s.selfEditableAttrs) > 0 {
		if u.Attributes == nil {
			u.Attributes = make(map[string]string, len(req.Attributes))
		}
		for k, v := range req.Attributes {
			if _, allowed := s.selfEditableAttrs[k]; allowed {
				u.Attributes[k] = v
			}
		}
	}
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), u); err != nil {
		s.logger.Error("update profile failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"user": u, KeyIss: s.resolveIssuer(ctx)})
}

// handleChangeMyPassword serves POST /me/password — the authenticated user
// changes their own password. Body: {current_password, new_password}. Verifies
// the current password against the credential store, then sets the new one.
//
// Credential endpoint: no-store headers. The caller is authenticated as their
// own account, so naming the wrong-current-password case (invalid_password) is
// not an enumeration leak — the user needs to know their entry was wrong. The
// store's VerifyPassword is itself anti-enumeration (dummy compare on unknown).
func (s *Server) handleChangeMyPassword(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	// bindOAuthParams accepts form-urlencoded + JSON (the §2 binder), unlike a
	// JSON-only decode. An empty current_password is rejected here so an
	// omitted field can never count as proof of the current credential (which
	// would otherwise pass against an empty-password account).
	if err := bindOAuthParams(ctx, &req); err != nil || req.NewPassword == "" || req.CurrentPassword == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if err := s.passwordCredentialStore.VerifyPassword(ctx.Request().Context(), userID, req.CurrentPassword); err != nil {
		// Wrong current password (or no credential): one response either way.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidPassword))
		return
	}
	if err := s.passwordCredentialStore.SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		s.logger.Error("set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// handleMyMFAFactors serves GET /me/mfa — lists the authenticated user's
// registered second factors (non-sensitive metadata only). Credential-adjacent;
// same cache headers as /userinfo.
func (s *Server) handleMyMFAFactors(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if factors == nil {
		factors = []core.MFAEnrolledFactor{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"factors": factors})
}

// handleDeleteMyMFAFactor serves DELETE /me/mfa/:id — unbinds one of the
// authenticated user's own factors. A factor belonging to another user (or a
// missing id) responds with the same 404 (oracle-safe: ownership is enforced
// via the user-scoped list, so a cross-user delete can never remove someone
// else's factor).
func (s *Server) handleDeleteMyMFAFactor(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	factorID := ctx.Param("id")
	if factorID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(factors, func(f core.MFAEnrolledFactor) bool { return f.ID == factorID }) {
		// Not owned by this user, or never existed — one response either way.
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if err := s.mfaEnrollmentStore.RemoveFactor(ctx.Request().Context(), userID, factorID); err != nil {
		s.logger.Error("remove mfa factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// handleTOTPEnrollBegin serves POST /me/mfa/totp/begin — the first leg of
// self-service TOTP enrollment. It mints a fresh secret and returns it (base32)
// plus an otpauth:// URI the SPA renders as a QR code. The secret is NOT
// persisted here: the flow is stateless, and the client returns it to the
// confirm leg alongside a code proving possession. Round-tripping the secret is
// safe because it only ever becomes a second factor for the caller's OWN
// authenticated account — no cross-user exposure. Credential-adjacent headers.
func (s *Server) handleTOTPEnrollBegin(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	if s.totpEnroller == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrTOTPEnrollmentNotSupported))
		return
	}
	secret, err := s.totpEnroller.GenerateSecret()
	if err != nil {
		s.logger.Error("totp enroll: generate secret failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"secret":      s.totpEnroller.EncodeSecret(secret),
		"otpauth_uri": s.totpEnroller.OTPAuthURI(s.resolveIssuer(ctx), userID, secret),
	})
}

// handleTOTPEnrollConfirm serves POST /me/mfa/totp/confirm — the second leg.
// Body: {secret, code, label?}. It verifies code against the supplied secret
// (proof of possession), then persists the secret + records the factor via the
// TOTPEnrollmentWriter so the factor is immediately usable at login AND listed
// by GET /me/mfa. Oracle-safe: a malformed secret and a wrong code collapse to
// one totp_invalid_code response; the operator-side cause lives only in the
// mfa_totp_enroll_failed audit event. Credential-adjacent headers.
func (s *Server) handleTOTPEnrollConfirm(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	writer, ok := s.mfaEnrollmentStore.(TOTPEnrollmentWriter)
	if !ok || s.totpEnroller == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrTOTPEnrollmentNotSupported))
		return
	}
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
		Label  string `json:"label"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.Secret == "" || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	secret, err := s.totpEnroller.DecodeSecret(req.Secret)
	if err != nil || !s.totpEnroller.VerifyCode(secret, req.Code) {
		// Bad secret encoding and wrong code collapse to one response.
		s.recordTOTPEnrollFailure(ctx, userID, "invalid_code")
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrTOTPInvalidCode))
		return
	}
	factorID, err := newMFAChallengeID()
	if err != nil {
		s.logger.Error("totp enroll: mint factor id failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "Authenticator app"
	}
	if err := writer.AddTOTPFactor(ctx.Request().Context(), userID, factorID, label, secret); err != nil {
		s.logger.Error("totp enroll: persist factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordTOTPEnrollSuccess(ctx, userID, factorID)
	ctx.JSON(http.StatusCreated, map[string]any{"factor_id": factorID, "label": label})
}

// recordTOTPEnrollSuccess / recordTOTPEnrollFailure emit the enrollment audit
// events. The secret is NEVER recorded; only the opaque factor_id (success) or
// the operator-side reason (failure, never returned to the caller).
func (s *Server) recordTOTPEnrollSuccess(ctx HandlerContext, userID, factorID string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventTOTPEnrolled,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "factor_id", factorID)
	s.auditor.Record(ctx.Request().Context(), evt)
}

func (s *Server) recordTOTPEnrollFailure(ctx HandlerContext, userID, reason string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventTOTPEnrollFailed,
		Outcome: audit.OutcomeFailure,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "reason", reason)
	s.auditor.Record(ctx.Request().Context(), evt)
}

// handleMyWebAuthnRegisterBegin serves POST /me/mfa/webauthn/begin — the first
// leg of AUTHENTICATED self-service passkey registration. The registration user
// is the BEARER SUBJECT (never request input), so the resulting credential can
// only bind to the caller's own account. Body: optional {display_name}. Returns
// {session_id, options} — the client passes options to navigator.credentials.create
// and returns session_id to the finish leg. Credential-adjacent headers.
func (s *Server) handleMyWebAuthnRegisterBegin(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	if s.webauthnRegistrar == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	// display_name is optional; an empty/missing body is fine (ignore bind error).
	_ = bindOAuthParams(ctx, &req)
	opts, sessionID, err := s.webauthnRegistrar.BeginRegistration(ctx.Request().Context(), userID, req.DisplayName)
	if err != nil {
		s.logger.Error("webauthn register begin failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"session_id": sessionID, "options": json.RawMessage(opts)})
}

// handleMyWebAuthnRegisterFinish serves POST /me/mfa/webauthn/finish?session_id=
// — verifies the attestation and commits the passkey, which then appears in
// GET /me/mfa. The session (from begin) determines the owning user, so the
// credential binds to the subject that began the ceremony; a valid bearer is
// still required so an unauthenticated caller can't drive finish. Failures
// collapse to one webauthn_registration_failed (cause in logs). Returns
// {credential_id}.
func (s *Server) handleMyWebAuthnRegisterFinish(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	if s.webauthnRegistrar == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	sessionID := ctx.Query("session_id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	credID, err := s.webauthnRegistrar.FinishRegistration(ctx.Request().Context(), sessionID, ctx.Request())
	if err != nil {
		s.logger.Error("webauthn register finish failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrWebAuthnRegistration))
		return
	}
	ctx.JSON(http.StatusCreated, map[string]any{"credential_id": credID})
}

// handleMySessions serves GET /sessions/me — lists the authenticated user's
// own active sessions. Session data is credential-adjacent so we apply the
// same cache-prevention headers as /token and /userinfo.
func (s *Server) handleMySessions(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list sessions failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if sessions == nil {
		sessions = []*core.Session{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"sessions": sessions})
}

// handleDeleteMySession serves DELETE /sessions/me/:id — lets a user revoke
// one of their own sessions. Sessions belonging to other users respond with
// the same 404 as a missing session (oracle-safe: don't reveal that a
// session exists but belongs to someone else).
func (s *Server) handleDeleteMySession(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	sessionID := ctx.Param("id")
	if sessionID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	sess, err := s.sessionMgr.Get(ctx.Request().Context(), sessionID)
	if err != nil || sess.UserID != userID {
		// Collapse not-found and wrong-user into one 404 (oracle-safe).
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if err := s.sessionMgr.Destroy(ctx.Request().Context(), sessionID); err != nil {
		s.logger.Error("destroy session failed", "session_id", sessionID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

// handleRevokeMySessions serves DELETE /sessions/me — "sign out everywhere".
// By default it revokes every active session of the authenticated user EXCEPT
// the one the caller is currently using (identified by the bearer token's SID
// claim), matching the near-universal "sign out of all other devices" UX so
// the user is not kicked out of the very portal issuing the request. Pass
// ?all=true to revoke the current session too (a full sign-out). When the
// token carries no SID (e.g. a stateless service token with no server-managed
// session), there is nothing to preserve and every session is revoked.
//
// Scope mirrors single-session revoke (DELETE /sessions/me/:id): it destroys
// sessions only. Bulk refresh-token revocation remains the OAuth-token concern
// of /token/revoke-all. Credential-adjacent, so the same no-store headers.
func (s *Server) handleRevokeMySessions(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	claims, ok := s.meClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), claims.Subject)
	if err != nil {
		s.logger.Error("list sessions failed", "user_id", claims.Subject, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	keepCurrent := claims.SID != "" && ctx.Query("all") != "true"
	revoked := 0
	for _, sess := range sessions {
		if keepCurrent && sess.ID == claims.SID {
			continue
		}
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), sess.ID); err != nil {
			s.logger.Error("destroy session failed", "session_id", sess.ID, "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
			return
		}
		revoked++
	}
	ctx.JSON(http.StatusOK, map[string]any{"revoked": revoked})
}

// handleMyConsents serves GET /consents/me — lists the authenticated user's
// consent grants. Credential-adjacent; same cache headers as /userinfo.
func (s *Server) handleMyConsents(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	grants, err := s.consentStore.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("list consents failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if grants == nil {
		grants = []core.ConsentGrant{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"consents": grants})
}

// handleDeleteMyConsent serves DELETE /consents/me/:client_id — revokes the
// authenticated user's consent grant for a given client. Idempotent per the
// ConsentStore contract; a missing grant returns 404.
func (s *Server) handleDeleteMyConsent(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	clientID := ctx.Param("client_id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if _, err := s.consentStore.GetConsent(ctx.Request().Context(), userID, clientID); err != nil {
		if errors.Is(err, core.ErrNoConsentGrant) {
			ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
			return
		}
		s.logger.Error("get consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.consentStore.RevokeConsent(ctx.Request().Context(), userID, clientID); err != nil {
		s.logger.Error("revoke consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordConsentEvent(ctx, audit.EventConsentRevoked, audit.OutcomeSuccess, userID, clientID, nil)
	ctx.JSON(http.StatusNoContent, nil)
}
