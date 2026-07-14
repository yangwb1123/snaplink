package sso

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// authenticateUser resolves the authenticator and validates credentials: a
// federated authenticator with a LoginURL redirects (handled=true); otherwise
// the per-account lockout gate runs BEFORE the verifier (so a locked account
// can't drain the constant-time hash budget), the credential is verified, and
// lockout state is updated (a failure may lock; a success clears the counter
// before any risk decision). Returns (result, handled) — handled=true means a
// response was written (redirect or rejection). Ordering is unchanged from the
// inline form.
func (s *Server) authenticateUser(ctx HandlerContext, req *login.Request, client *Client) (*AuthResult, bool) {
	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrUnsupportedProvider, req.State))
		return nil, true
	}
	if loginURL := auth.LoginURL(req.State); loginURL != "" {
		ctx.Redirect(http.StatusFound, loginURL)
		return nil, true
	}
	lockKey := s.lockoutKey(auth, req.ClientID, req.Credential)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.IsLocked(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))
			return nil, true
		}
	}
	result, err := auth.Authenticate(ctx.Request().Context(), &AuthRequest{
		Provider:        req.Provider,
		Credential:      req.Credential,
		ClientID:        req.ClientID,
		Scope:           req.Scope,
		State:           req.State,
		LoginHint:       req.LoginHint,
		ACRValues:       splitScope(req.ACRValues),
		UILocales:       splitScope(req.UILocales),
		RequestedClaims: oauth.CloneRawJSON(req.Claims),
	})
	if err != nil {
		s.handleAuthFailure(ctx, req, lockKey, err)
		return nil, true
	}
	if s.rejectDeactivatedUser(ctx, req, result.UserID) {
		return nil, true
	}
	// A single legit login resets the brute-force budget (before risk evaluation).
	if s.accountLockout != nil && lockKey != "" {
		_ = s.accountLockout.RegisterSuccess(ctx.Request().Context(), lockKey)
	}
	return result, false
}

// handleAuthFailure writes the authentication-failure response: it attributes the
// failure to per-account lockout (and emits account_locked when that trips)
// BEFORE the generic login_failure audit, then collapses to invalid_credentials
// — UNLESS the authenticator flagged the failure as a stateful ceremony problem
// (core.ErrCeremonySessionInvalid), in which case it renders the SAME
// oracle-safe 404 session_invalid a ceremony's own dedicated endpoint would
// (e.g. WebAuthn's /webauthn/login/*): a client must not be able to tell
// "unknown session" from "unknown user" by response shape, nor tell it
// reached that state via /auth/login vs. the ceremony's own endpoint.
func (s *Server) handleAuthFailure(ctx HandlerContext, req *login.Request, lockKey string, err error) {
	s.logErrorCtx(ctx, "authentication failed", "provider", req.Provider, "error", err)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.RegisterFailure(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))
			return
		}
	}
	if errors.Is(err, core.ErrCeremonySessionInvalid) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrSessionInvalid)
		ctx.JSON(http.StatusNotFound, s.authzErrorBodyWithState(ctx, core.ErrSessionInvalid, req.State))
		return
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidCredentials)
	ctx.JSON(http.StatusUnauthorized, s.authzErrorBodyWithState(ctx, core.ErrInvalidCredentials, req.State))
}

// rejectDeactivatedUser enforces SCIM deprovisioning (RFC 7643 active=false):
// even with a correct credential, a deactivated account MUST NOT obtain tokens.
// Called AFTER credential verification, BEFORE any token/session side effect, so
// an IdP connector that PATCHed active=false actually revokes access. Collapses
// to account_locked (an unavailable account, not a credential oracle: the
// credential already verified). No UserProvider = no SCIM state = no-op; a
// not-found user (federated/first login) is treated active. Returns true (with a
// response written) when the login must be rejected.
func (s *Server) rejectDeactivatedUser(ctx HandlerContext, req *login.Request, userID string) bool {
	if s.userProvider == nil {
		return false
	}
	u, uerr := s.userProvider.GetByID(ctx.Request().Context(), userID)
	if uerr != nil || u.IsActive() {
		return false
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrAccountLocked)
	ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))
	return true
}

// lockoutKey derives the per-account brute-force lockout key. An authenticator
// that implements LockoutKeyer reports its OWN canonical, normalized identity
// field — authoritative: a credential it declares unkeyable ("") skips the gate
// rather than falling back to the spoofable field precedence (which an attacker
// could defeat by injecting a higher-precedence field the authenticator ignores,
// or by varying case/whitespace). Authenticators without it use the generic
// security.LockoutKey precedence (correct when their identity field is the first
// present, e.g. password's username).
func (s *Server) lockoutKey(auth Authenticator, clientID string, cred map[string]string) string {
	if lk, ok := auth.(LockoutKeyer); ok {
		id := lk.LockoutIdentity(cred)
		if id == "" {
			return ""
		}
		return clientID + ":" + id
	}
	return security.LockoutKey(clientID, cred)
}

// enforceLoginACR applies OIDC §3.1.2.6 / §5.5.1.1 ACR enforcement: the RP may
// demand ACR values via acr_values OR the claims parameter's id_token.acr entry,
// honored with identical strictness. Empty union = no constraint; a present list
// with no matching AchievedACR fails with the spec error (oracle-safe — the
// achieved ACR is never revealed). Returns true when it wrote an error response.
func (s *Server) enforceLoginACR(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	acrList := splitScope(req.ACRValues)
	if len(req.Claims) > 0 {
		acrList = append(acrList, oauth.RequestedACRFromClaims(req.Claims)...)
	}
	if len(acrList) > 0 && !slices.Contains(acrList, result.AchievedACR) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrUnmetAuthReqs)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrUnmetAuthReqs, req.State))
		return true
	}
	return false
}

// enforceLoginMaxAge enforces OIDC Core §3.1.2.6 max_age. Fresh
// credentials always satisfy any max_age window (AuthTime=now).
func (s *Server) enforceLoginMaxAge(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	if req.MaxAge == nil {
		return false
	}
	// max_age=0 → require fresh auth (user provided credentials ✓).
	// max_age=N → auth must be within N seconds (AuthTime=now ✓).
	// Issuance path sets AuthTime = time.Now() in tokens.
	return false
}

// rejectUnverifiedEmail returns true when mandatory email verification is
// enabled AND the authenticated user's email is not yet verified. The check
// occurs AFTER credential verification (oracle-safe: an attacker who knows
// the password cannot distinguish "user doesn't exist" from "unverified").
func (s *Server) rejectUnverifiedEmail(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	if !s.signupRequireVerification {
		return false
	}
	if s.userProvider == nil {
		return false
	}
	u, uerr := s.userProvider.GetByID(ctx.Request().Context(), result.UserID)
	// Fail closed: a store error or missing record cannot confirm verified status.
	if uerr != nil || u == nil || u.Attributes["email_verified"] != "true" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrEmailNotVerified)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrEmailNotVerified, req.State))
		return true
	}
	return false
}

// rejectExpiredPassword returns true when the operator has configured
// PasswordPolicyConfig.MaxAgeDays > 0 (via WithPasswordPolicy) AND this login
// used the password factor AND the credential has aged past that window.
// Runs AFTER credential verification, alongside rejectUnverifiedEmail (same
// call site, same shape): the user has ALREADY proved they hold the CURRENT
// password, so "expired" here is a POLICY-STATE signal the client must react
// to (route the user through a forced change-password flow before retrying),
// NOT a credential-validity oracle — an attacker without the correct password
// never reaches this check, so a distinct code leaks nothing about whether a
// guessed password was ever valid (AGENTS.md §3 Anti-Enumeration).
//
// Fails OPEN (returns false = proceed) at every point the signal is
// unavailable: no policy wired, MaxAgeDays<=0, this login didn't use the
// password factor (result.AuthMethods lacks core.AMRPassword — e.g. WebAuthn/
// federated logins are unaffected), no PasswordCredentialStore wired, the
// wired store doesn't implement core.PasswordAgeReader, or the age lookup
// errors. A deployment that hasn't opted in (or hits any of those gaps) is
// byte-identical to before this feature.
func (s *Server) rejectExpiredPassword(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	maxAgeDays := s.passwordMaxAgeDays()
	if maxAgeDays <= 0 || !slices.Contains(result.AuthMethods, core.AMRPassword) {
		return false
	}
	reader, ok := s.passwordCredentialStore.(core.PasswordAgeReader)
	if !ok {
		return false
	}
	changedAt, err := reader.PasswordChangedAt(ctx.Request().Context(), result.UserID)
	if err != nil || time.Since(changedAt) < time.Duration(maxAgeDays)*24*time.Hour {
		return false
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrPasswordExpired)
	ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrPasswordExpired, req.State))
	return true
}
