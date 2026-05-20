package sso

import (
	"net/http"
	"strings"
)

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
//   - Requested token type access_token (default).
//   - resource + audience (merged into the new token's aud claim).
//   - Scope narrowing (subset of the subject token's scopes).
//
// Future-scope (deliberately deferred for v1):
//   - Refresh token output (no compelling caller need yet).
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
		req.RequestedTokenType != TokenTypeAccessToken {
		// v1 only mints access tokens. Refresh / ID token output is
		// future work — caller wanted something we can't deliver.
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}

	claims, _, err := s.validateAnyToken(ctx.Request().Context(), req.SubjectToken)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
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
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:        claims.Subject,
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
	}, scopes)
	if err != nil {
		s.logger.Error("token exchange issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordTokenIssued(ctx, client.ID, strategy, claims.Subject)
	s.recordSubjectClientAccess(ctx.Request().Context(), claims.Subject, client.ID)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyAccessToken:     token.AccessToken,
		KeyIssuedTokenType: TokenTypeAccessToken,
		KeyTokenType:       token.TokenType,
		KeyExpiresIn:       token.ExpiresIn,
		KeyScope:           token.Scope,
		KeyTokenStrategy:   strategy,
	})
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
}

// mergeTargets deduplicates a slice of resource / audience URIs
// while preserving the first-occurrence order. Both RFC 8707
// `resource` and RFC 8693 `audience` express the same intent;
// merging lets callers use whichever vocabulary their tooling
// favors without changing the token contents.
func mergeTargets(primary, secondary []string) []string {
	if len(primary) == 0 && len(secondary) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(primary)+len(secondary))
	out := make([]string, 0, len(primary)+len(secondary))
	for _, s := range primary {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range secondary {
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
