package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/protocols/oauth"
)

// issueAuthCode delegates to oauth.IssueAuthCode. confirmationJKT is the RFC
// 9449 §10 DPoP key thumbprint captured off the /auth/login request (empty =
// unbound); see captureAuthCodeDPoPBinding.
func (s *Server) issueAuthCode(ctx context.Context, result *AuthResult, req *login.Request, client *Client, confirmationJKT string) (string, error) {
	return oauth.IssueAuthCode(ctx, oauth.IssueAuthCodeParams{
		AuthCodeTTL:          s.authCodeTTL,
		AuthCodeStore:        s.authCodeStore,
		UserID:               result.UserID,
		ClientID:             client.ID,
		RedirectURI:          req.RedirectURI,
		Scopes:               req.Scope,
		Nonce:                req.Nonce,
		Provider:             result.Provider,
		AuthMethods:          result.AuthMethods,
		ACR:                  result.AchievedACR,
		Attributes:           result.Attributes,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resources:            req.Resource,
		AuthorizationDetails: req.AuthorizationDetails,
		ConfirmationJKT:      confirmationJKT,
		// OIDC Core §5.5: persist the claims parameter on the code so the
		// /token exchange projects it exactly like the direct-mint flow.
		RequestedClaims: req.Claims,
	})
}

// captureAuthCodeDPoPBinding validates an optional DPoP proof presented AT
// AUTHORIZATION TIME (/auth/login) and returns its JWK thumbprint so the
// issued authorization code can be bound to it (RFC 9449 §10) — closing the
// code-injection gap where an attacker who intercepts a code minted for one
// client's DPoP key redeems it under a key of their own. This is DISTINCT
// from captureSenderConstraint (server_token.go), which binds the eventual
// access/refresh token to whatever proof arrives separately at the /token
// EXCHANGE — the two proofs may even be presented by different requests, so
// they are captured and validated independently.
//
// Absence of the header is NOT an error: DPoP code-binding is opt-in,
// exactly like the token-binding path. handled==true means an error
// response has ALREADY been written (the authz error envelope + RFC 6749
// §4.1.2.1 state echo, per AGENTS.md "New authz handlers MUST use
// s.authzErrorBodyWithState") and the caller MUST return.
func (s *Server) captureAuthCodeDPoPBinding(ctx HandlerContext, state string) (dpopJKT string, handled bool) {
	proof := ctx.Request().Header.Get(HeaderDPoP)
	if proof == "" {
		return "", false
	}
	binding, err := verifyDPoPProof(
		ctx.Request().Context(),
		proof,
		ctx.Request().Method,
		requestURLForDPoP(ctx.Request()),
		s.jtiReplayStore,
		s.jtiReplayFailClosed,
		s.dpopNonceProvider,
		s.resolvedDPoPProofMaxAge(),
		s.resolvedDPoPProofClockSkew(), "", // issuance: no access token yet, no ath
	)
	if err != nil {
		if errors.Is(err, ErrDPoPNonceRequired) {
			s.stampDPoPNonce(ctx)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrUseDPoPNonce, state))
			return "", true
		}
		s.logger.Error("dpop proof failed at authorization endpoint", "error", err)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidDPoPProof, state))
		return "", true
	}
	return binding.JKT, false
}

// isSecureRedirectURI delegates to oauth.IsSecureRedirectURI.
func isSecureRedirectURI(uri string) bool {
	return oauth.IsSecureRedirectURI(uri)
}

// isValidPKCEMethod delegates to oauth.IsValidPKCEMethod.
func isValidPKCEMethod(method string) bool {
	return oauth.IsValidPKCEMethod(method)
}

// isPKCEMethodAllowedForClient delegates to oauth.IsPKCEMethodAllowedForClient.
func isPKCEMethodAllowedForClient(method string, allowed []string) bool {
	return oauth.IsPKCEMethodAllowedForClient(method, allowed)
}

// generateAuthCodeBytes delegates to oauth.GenerateAuthCodeBytes.
func generateAuthCodeBytes() (string, error) {
	return oauth.GenerateAuthCodeBytes()
}

// issueRefreshToken delegates to oauth.IssueRefreshToken.
func (s *Server) issueRefreshToken(
	ctx context.Context,
	userID, clientID, provider string,
	scopes []string,
	attributes map[string]string,
	familyID string,
	resources []string,
	authDetails []byte,
	sid string,
	authCtx oauth.RefreshAuthContext,
	clientTTLOverride time.Duration,
	confirmationJKT string,
) (string, error) {
	return oauth.IssueRefreshToken(ctx, oauth.IssueRefreshTokenParams{
		RefreshTokenTTL:      s.refreshTokenTTL,
		RefreshTokenStore:    s.refreshTokenStore,
		UserID:               userID,
		ClientID:             clientID,
		Provider:             provider,
		Scopes:               scopes,
		Attributes:           attributes,
		FamilyID:             familyID,
		Resources:            resources,
		AuthorizationDetails: authDetails,
		SID:                  sid,
		AMR:                  authCtx.AMR,
		ACR:                  authCtx.ACR,
		AuthTime:             authCtx.AuthTime,
		ClientTTLOverride:    clientTTLOverride,
		ConfirmationJKT:      confirmationJKT,
		Generation:           authCtx.Generation,
		FamilyCreatedAt:      authCtx.FamilyCreatedAt,
	})
}

// isScopeSubset delegates to oauth.IsScopeSubset.
func isScopeSubset(want, have []string) bool {
	return oauth.IsScopeSubset(want, have)
}

// handleCallback handles the OAuth callback. This remains in root as it's a Server HTTP handler.
func (s *Server) handleCallback(ctx HandlerContext) {
	// The callback success response returns a session_id credential; mark it
	// non-cacheable (a GET is otherwise cacheable by intermediaries).
	tokenNoStoreHeaders(ctx)
	code := ctx.Query("code")
	state := ctx.Query("state")
	provider := ctx.Query("provider")

	if code == "" || state == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return
	}

	auth, ok := s.resolveCallbackAuthenticator(ctx, provider, code, state)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrUnknownProvider))
		return
	}

	result, err := auth.Callback(context.Background(), &CallbackState{Code: code, State: state})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrCallbackFailed))
		return
	}

	s.finalizeCallbackSession(ctx, result)
}

// resolveCallbackAuthenticator picks the authenticator that owns this callback.
// When provider is named it looks it up directly; otherwise it probes each
// registered authenticator's Callback to find one that accepts the code/state.
// NOTE: this probe deliberately CALLS a.Callback to resolve the owner — the
// parent then calls auth.Callback AGAIN. The double-call is intentional (it
// preserves the original per-attempt side effects) and must not be collapsed.
func (s *Server) resolveCallbackAuthenticator(ctx HandlerContext, provider, code, state string) (Authenticator, bool) {
	if provider != "" {
		auth, _ := s.getAuthenticator(provider)
		if auth == nil {
			// Enterprise-connection round-trip: the upstream IdP redirected back
			// from a flow /auth/login dispatched via provider=<connection id>, so
			// the callback owner is factory-built, not statically registered.
			// Routed through the SAME cross-tenant guard as the login leg
			// (connectionLoginAuthenticator): a callback served under one tenant's
			// hostname must not resolve another org's connection, and every miss
			// collapses to the identical unknown_provider response — no 400-vs-401
			// or outbound-fetch timing oracle over cross-tenant connection ids.
			auth, _ = s.connectionLoginAuthenticator(ctx, provider)
		}
		return auth, auth != nil
	}
	for _, a := range s.authenticators {
		if _, err := a.Callback(context.Background(), &CallbackState{Code: code, State: state}); err == nil {
			return a, true
		}
	}
	return nil, false
}

// errMaxActiveSessions is the sentinel createSession returns when a wired
// token-policy max_active_sessions cap would be exceeded by minting another
// session for this (user, client). Unlike the tenant-quota path, createSession
// writes NO response for it — the login caller maps it to a clean access_denied
// and owns the single wire write, so there is no double WriteHeader.
var errMaxActiveSessions = errors.New("sso: max active sessions reached")

// sessionPolicyCapExceeded reports whether minting another session for (userID,
// clientID) would breach the wired token-policy max_active_sessions dimension.
// Default-OFF: a nil token-policy store returns false immediately, so a login
// with no policy wired is byte-identical to before the feature. This is a
// GOVERNANCE property, not a credential check — every uncertainty FAILS OPEN
// (returns false, allow the session): a policy-store load error or a ListByUser
// count error must never block a legitimate login (same stance as
// tenant-suspension / risk-scorer, AGENTS.md §3 Fail Modes). It reuses
// ListByUser — the same enumerator the WithMaxSessionsPerUser eviction cap uses
// — to count the subject's live sessions, and enforces the cap BEFORE the mint
// so an over-cap login is refused rather than evicting a peer session.
func (s *Server) sessionPolicyCapExceeded(ctx HandlerContext, userID, clientID string) bool {
	if s.tokenPolicyStore == nil || s.sessionMgr == nil {
		return false
	}
	policies, err := s.tokenPolicyStore.Policies(ctx.Request().Context())
	if err != nil {
		s.logger.Error("token policy load failed — allowing session (fail-open)", "error", err)
		return false
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("session cap: list by user failed — allowing session (fail-open)",
			"error", err, "user", userID)
		return false
	}
	dec := tokenpolicy.Evaluate(tokenpolicy.PolicyInput{
		ClientID:       clientID,
		Subject:        userID,
		ActiveSessions: len(sessions),
	}, policies)
	// Only the active-sessions dimension can fire on this seam (no scopes / no
	// refresh depth supplied); guard on the reason so an unrelated deny can never
	// block a login.
	if !dec.Deny || dec.Reason != tokenpolicy.DenyActiveSessions {
		return false
	}
	s.metrics.ObserveTokenPolicyEvaluation(metrics.PolicyDecisionDeny)
	s.metrics.ObserveTokenPolicyDenial(string(dec.Reason))
	s.logger.Info("token policy denied session creation",
		"client", clientID, "user", userID, "active", len(sessions))
	return true
}

// IntrospectionRenewExceeded moved to sso_protocol.go (which had room) to
// keep this file within the per-file line budget.

// finalizeCallbackSession upserts the user (when a UserProvider is configured)
// and creates a session, writing the success or 500 error response.
func (s *Server) finalizeCallbackSession(ctx HandlerContext, result *AuthResult) {
	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if s.userProvider != nil {
		// Gate: reject deprovisioned users (SCIM active=false) before creating a
		// session — mirrors rejectDeactivatedUser on the password/LDAP path. A
		// not-found user (first federated login) is treated active (no SCIM state).
		if u, err := s.userProvider.GetByID(ctx.Request().Context(), result.UserID); err == nil && u != nil && !u.IsActive() {
			s.logger.Info("federated callback blocked: account deprovisioned", "user_id", result.UserID, "provider", result.Provider)
			ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrCallbackFailed))
			return
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
			return
		}
	}

	// Federated callback has no OAuth client in play — pass an empty clientID
	// (and tenant), so only a fleet-wide (empty-selector) max_active_sessions
	// policy applies to this login.
	session, err := s.createSession(ctx, result.UserID, "", "")
	if err != nil {
		if errors.Is(err, errMaxActiveSessions) {
			ctx.JSON(http.StatusForbidden, errorBody(ctx, ErrAccessDenied))
			return
		}
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	s.linkGlobalSession(ctx.Request().Context(), session, result.UserID)

	ctx.JSON(http.StatusOK, map[string]string{
		KeySessionID: session.ID,
		KeyStatus:    StatusAuthenticated,
	})
}

func (s *Server) requireDeps(deps ...string) error {
	for _, d := range deps {
		switch d {
		case DepTokenIssuer:
			if len(s.tokenIssuers) == 0 {
				return fmt.Errorf("at least one TokenIssuer is required")
			}
		case DepUserProvider:
			if s.userProvider == nil {
				return fmt.Errorf("UserProvider is required")
			}
		case DepClientStore:
			if s.clientStore == nil {
				return fmt.Errorf("ClientStore is required")
			}
		case DepSessionMgr:
			if s.sessionMgr == nil {
				return fmt.Errorf("SessionManager is required")
			}
		}
	}
	return nil
}
