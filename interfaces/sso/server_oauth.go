package sso

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/snaplink/sso/internal/handler"

	"github.com/snaplink/sso/domains/tokenpolicy"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/protocols/oauth"
)

// issueAuthCode delegates to oauth.IssueAuthCode.
func (s *Server) issueAuthCode(ctx context.Context, result *AuthResult, req *login.Request, client *Client) (string, error) {
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
	})
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
	})
}

// isScopeSubset delegates to oauth.IsScopeSubset.
func isScopeSubset(want, have []string) bool {
	return oauth.IsScopeSubset(want, have)
}

// providersForClient returns the list of authenticator names this client may use.
// This remains in root as it's a Server adapter method.
func (s *Server) providersForClient(ctx HandlerContext, clientID string) []string {
	all := make([]string, 0, len(s.authenticators))
	for name := range s.authenticators {
		all = append(all, name)
	}
	if clientID == "" || s.clientStore == nil {
		return all
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		return all
	}
	if len(client.AllowedAuthenticators) == 0 {
		return all
	}
	out := make([]string, 0, len(all))
	for _, name := range all {
		if client.IsAuthenticatorAllowed(name) {
			out = append(out, name)
		}
	}
	return out
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
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidCallback))
		return
	}

	auth, ok := s.resolveCallbackAuthenticator(provider, code, state)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnknownProvider))
		return
	}

	result, err := auth.Callback(context.Background(), &CallbackState{Code: code, State: state})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrCallbackFailed))
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
func (s *Server) resolveCallbackAuthenticator(provider, code, state string) (Authenticator, bool) {
	if provider != "" {
		auth, _ := s.getAuthenticator(provider)
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

// IntrospectionRenewExceeded reports whether an access token being introspected
// has passed its wired require_renew fraction of TTL and should be reported
// INACTIVE (governance force-refresh). Default-OFF: a nil token-policy store
// returns false, so introspection is byte-identical without a wired policy.
// FAIL-OPEN on a store error (false) — a governance-store outage must never
// flip a cryptographically valid token to inactive. Bumps the renew-required
// metric on a positive result (the only place that governance signal surfaces).
func (s *Server) IntrospectionRenewExceeded(ctx context.Context, clientID string, scopes []string, issuedAt, expiresAt time.Time) bool {
	if s.tokenPolicyStore == nil {
		return false
	}
	policies, err := s.tokenPolicyStore.Policies(ctx)
	if err != nil {
		s.logger.Error("token policy load failed — reporting token active (fail-open)", "error", err)
		return false
	}
	dec := tokenpolicy.Evaluate(tokenpolicy.PolicyInput{
		ClientID: clientID,
		Scopes:   scopes,
		Kind:     tokenpolicy.KindAccess,
	}, policies)
	if !tokenpolicy.RenewExceeded(dec.RenewAfter, issuedAt, expiresAt, time.Now()) {
		return false
	}
	s.metrics.ObserveTokenPolicyRenewRequired()
	s.logger.Info("token past require_renew threshold — reported inactive at introspection",
		"client", clientID)
	return true
}

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
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrCallbackFailed))
			return
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
	}

	// Federated callback has no OAuth client in play — pass an empty clientID
	// (and tenant), so only a fleet-wide (empty-selector) max_active_sessions
	// policy applies to this login.
	session, err := s.createSession(ctx, result.UserID, "", "")
	if err != nil {
		if errors.Is(err, errMaxActiveSessions) {
			ctx.JSON(http.StatusForbidden, errorBody(ErrAccessDenied))
			return
		}
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, map[string]string{
		KeySessionID: session.ID,
		KeyStatus:    StatusAuthenticated,
	})
}

func (s *Server) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	claims, _, err := s.validateAnyToken(ctx, token)
	return claims, err
}

// validateTokenPreChecks runs the two Server-level defense-in-depth gates
// BEFORE any issuer sees the token: a byte-length ceiling (WithMaxTokenBytes)
// and the JWS `alg` allowlist (WithSupportedSigningAlgs). Split out of
// validateAnyToken to keep it within the function-length budget; both
// checks are unbounded/no-op (nil error) unless the operator configured
// them, so this is byte-identical to today when neither option is wired.
func (s *Server) validateTokenPreChecks(token string) error {
	// Byte-length gate: a caller handing the server a deliberately huge
	// "token" string shouldn't get to spend CPU on base64 + JSON parsing
	// before the eventual (inevitable) verification failure. The generic
	// error below is intentional: every caller of validateAnyToken already
	// collapses ANY non-nil error to the standard oracle-safe
	// invalid_token/inactive response, never inspecting content.
	if s.maxTokenBytes > 0 && len(token) > s.maxTokenBytes {
		return fmt.Errorf("token exceeds max_token_bytes (%d)", s.maxTokenBytes)
	}
	// alg allowlist gate: reject any compact-JWS bearer whose header `alg`
	// isn't allowed BEFORE any issuer runs — so the verification algorithm
	// is fixed by the operator, never picked by the RP. Opaque (non-JWT)
	// tokens carry no JOSE header and pass through untouched to the
	// session/opaque issuers.
	if len(s.supportedSigningAlgs) > 0 {
		if alg, ok := jwsHeaderAlg(token); ok && !algAllowed(alg, s.supportedSigningAlgs) {
			return fmt.Errorf("token alg %q not in supported_signing_algs", alg)
		}
	}
	return nil
}

// validateAnyToken tries each registered issuer until one accepts the token.
// Returned issuerName lets callers correlate revocations or audit logs.
func (s *Server) validateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	if err := s.validateTokenPreChecks(token); err != nil {
		return nil, "", err
	}
	var lastErr error
	for name, ti := range s.tokenIssuers {
		// Skip issuers that explicitly opt out of this token's shape.
		// Saves an expensive base64 + signature attempt when a session
		// token reaches the JWT issuer or vice versa. Issuers without
		// a TokenFormatHinter are always tried (legacy behavior).
		if h, ok := ti.(TokenFormatHinter); ok && !h.AcceptsTokenFormat(token) {
			continue
		}
		claims, err := ti.Validate(ctx, token)
		if err == nil {
			// Post-validation tenant suspension gate.
			// No-op when WithTenantSuspensionCheck wasn't passed; otherwise
			// hard-fails tokens whose owning client belongs to a now-
			// suspended tenant so an admin's Suspended flip cuts off
			// already-issued bearers, not just future issuance.
			if tsErr := s.checkTenantNotSuspended(ctx, claims); tsErr != nil {
				return nil, "", tsErr
			}
			// TODO(region): read-side residency on validate needs serving-region
			// plumbing. validateAnyToken takes a bare context.Context (no
			// HandlerContext), and the serving region is stashed on the
			// HandlerContext by region.Middleware — it is NOT in scope here.
			// Threading it would change validateAnyToken + ValidateToken +
			// every call site (userinfo / mesh ext_authz / introspect / admin /
			// token-exchange) — too invasive for this commit. The login
			// (write/mint) gate in handler.go is the primary residency control;
			// the read-side check (isWrite=false, only region_not_allowed can
			// fire) lands once the serving region is plumbed onto validate.
			return claims, name, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no token issuers registered")
	}
	return nil, "", lastErr
}

// revokeAcrossIssuers asks every registered issuer to revoke the token.
// Revoke is expected to be tolerant of unknown tokens (the issuer that
// doesn't own the token returns ErrNoSuchToken or similar — that's a
// no-op, not a failure). Returns:
//
//   - revoked: names of issuers whose Revoke returned nil.
//   - failed: names of issuers whose Revoke returned a non-nil, non-
//     "unknown token" error — these are the ones where the bearer
//     may still work and the caller should audit
//     `partial_revoke_failure`.
//
// The split lets the caller distinguish "no issuer owned this token"
// (revoked empty, failed empty — benign) from "an issuer that DOES
// own this token failed to revoke" (revoked empty, failed non-empty
// — bug or infra issue that violates the logout-everywhere promise).
func (s *Server) revokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string) {
	for name, ti := range s.tokenIssuers {
		// Honor the same shape-skip the validate path uses. An
		// issuer whose TokenFormatHinter rejects the inbound token
		// can't possibly own it, so asking it to Revoke would either
		// (a) return a not-found error we ignore anyway, or (b)
		// return an infra error we'd misclassify as a partial
		// revoke failure. Skip cleanly.
		if h, ok := ti.(TokenFormatHinter); ok && !h.AcceptsTokenFormat(token) {
			continue
		}
		switch err := ti.Revoke(ctx, token); {
		case err == nil:
			revoked = append(revoked, name)
		case isUnknownTokenErr(err):
			// Issuer didn't own this token — expected when callers
			// sweep across N issuers. Not a failure.
		default:
			failed = append(failed, name)
		}
	}
	return revoked, failed
}

// isUnknownTokenErr heuristically classifies an issuer's Revoke
// error. The error surface across issuers is loose (each impl
// returns its own sentinel — Ed25519 issuer returns nil for
// stateless tokens; SessionTokenIssuer returns "session_issuer:
// token not found"). Treat the standard "not found" / "unknown"
// shapes as no-op; everything else is infra failure worth auditing.
// When an issuer adopts a typed sentinel (e.g. ErrUnknownToken), add
// it here.

func isUnknownTokenErr(err error) bool           { return handler.IsUnknownTokenErr(err) }
func jwsHeaderAlg(token string) (string, bool)   { return handler.JWSHeaderAlg(token) }
func algAllowed(alg string, allow []string) bool { return handler.AlgAllowed(alg, allow) }

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
