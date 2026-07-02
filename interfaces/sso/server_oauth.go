package sso

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/snaplink/sso/internal/handler"

	"github.com/snaplink/sso/internal/auth/login"
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
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return
	}

	auth, ok := s.resolveCallbackAuthenticator(provider, code, state)
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

	session, err := s.createSession(ctx, result.UserID, "")
	if err != nil {
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
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

// validateAnyToken tries each registered issuer until one accepts the token.
// Returned issuerName lets callers correlate revocations or audit logs.
func (s *Server) validateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	// Server-level alg allowlist gate (defense-in-depth). When
	// configured via WithSupportedSigningAlgs, reject any compact-JWS
	// bearer whose header `alg` isn't allowed BEFORE any issuer runs —
	// so the verification algorithm is fixed by the operator, never
	// picked by the RP. Opaque (non-JWT) tokens carry no JOSE header
	// and pass through untouched to the session/opaque issuers.
	if len(s.supportedSigningAlgs) > 0 {
		if alg, ok := jwsHeaderAlg(token); ok && !algAllowed(alg, s.supportedSigningAlgs) {
			return nil, "", fmt.Errorf("token alg %q not in supported_signing_algs", alg)
		}
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
