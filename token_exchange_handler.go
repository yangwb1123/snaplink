package sso

//   - missing subject_token / subject_token_type → 400 invalid_request
import (
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/core"
)
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
