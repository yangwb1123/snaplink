package sso

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/selfservice"
	"github.com/snaplink/sso/protocols/selfservice/selfservicecore"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// handleSelfRegister delegates to selfservice.HandleSelfRegister.
func (s *Server) handleSelfRegister(ctx HandlerContext) {
	selfservice.HandleSelfRegister(s, ctx)
}

// handleVerifyEmail delegates to selfservice.HandleVerifyEmail.
func (s *Server) handleVerifyEmail(ctx HandlerContext) {
	selfservice.HandleVerifyEmail(s, ctx)
}

// Deps interface implementation for selfservice.Deps

// UserProvider returns the user provider.
func (s *Server) UserProvider() UserProvider {
	return s.userProvider
}

// PasswordCredentialStore returns the password credential store.
func (s *Server) PasswordCredentialStore() PasswordCredentialStore {
	return s.passwordCredentialStore
}

// EmailChangeStore returns the email change store.
func (s *Server) EmailChangeStore() EmailChangeStore {
	return s.emailChangeStore
}

// PasswordResetStore returns the password reset store.
func (s *Server) PasswordResetStore() PasswordResetStore {
	return s.passwordResetStore
}

// EmailChangeTTL returns the email change token TTL.
func (s *Server) EmailChangeTTL() time.Duration {
	return s.emailChangeTTL
}

// PasswordResetTTL returns the password reset token TTL.
func (s *Server) PasswordResetTTL() time.Duration {
	return s.passwordResetTTL
}

// PasswordResetResolver returns the password reset resolver function.
func (s *Server) PasswordResetResolver() func(ctx context.Context, identifier string) (string, error) {
	return s.passwordResetResolver
}

// PasswordResetDeliveryResolver returns the password reset delivery resolver function.
func (s *Server) PasswordResetDeliveryResolver() func(ctx context.Context, userID string) (string, error) {
	return s.passwordResetDeliveryResolver
}

// PasswordResetSender returns the password reset sender.
func (s *Server) PasswordResetSender() spi.PasswordResetSender {
	return s.passwordResetSender
}

// SessionManager returns the session manager.
func (s *Server) SessionManager() SessionManager {
	return s.sessionMgr
}

// Logger returns the logger.
func (s *Server) Logger() spi.Logger {
	return s.logger
}

// GenerateAuthCodeBytes delegates to oauth.GenerateAuthCodeBytes.
func (s *Server) GenerateAuthCodeBytes() (string, error) {
	return generateAuthCodeBytes()
}

// TokenNoStoreHeaders sets no-store headers.
func (s *Server) TokenNoStoreHeaders(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
}

// resolvedSecurityHeadersPolicy returns the operator-supplied CSP/Permissions-
// Policy override (WithSecurityHeadersPolicy), or the zero value when unset —
// handler.SecurityHeaders resolves a zero-value field to
// handler.DefaultSecurityHeadersPolicy itself, so callers never need to.
func (s *Server) resolvedSecurityHeadersPolicy() handler.SecurityHeadersPolicy {
	if s.securityHeadersPolicy != nil {
		return *s.securityHeadersPolicy
	}
	return handler.SecurityHeadersPolicy{}
}

// wrapSecurityHeaders applies the security-headers middleware (CSP +
// Permissions-Policy + per-request nonce + the existing default-deny headers)
// to h when WithSecurityHeaders/WithSecurityHeadersPolicy is wired. Used for
// the opt-in SPA bundles (admin console, hosted login, portal), which are
// served OUTSIDE the SSO router's own middleware chain (buildProbeMux) and so
// need this applied explicitly. No-op (returns h unchanged) when the feature
// is off — byte-identical to a build without it.
func (s *Server) wrapSecurityHeaders(h http.Handler) http.Handler {
	if !s.securityHeadersEnabled {
		return h
	}
	return handler.SecurityHeaders(s.resolvedSecurityHeadersPolicy())(h)
}

// ClearSiteData sets the Clear-Site-Data response header — instructing the
// browser to purge cache/cookies/storage for this origin — when security
// headers are enabled (WithSecurityHeaders / WithSecurityHeadersPolicy).
// Callers use this ONLY on a DEFINITIVE end to the session on this origin
// (POST /logout, POST /me/account/erase when not a dry run) — never on a
// per-token revoke, which may leave other sessions/tabs on this origin
// alive. No-op (byte-identical) when security headers are not enabled.
func (s *Server) ClearSiteData(ctx HandlerContext) {
	if !s.securityHeadersEnabled {
		return
	}
	middleware.ClearSiteData(ctx)
}

// ErrorBody creates an error response body.
//
// selfservicecore.Deps.ErrorBody has no HandlerContext parameter (it
// predates trace-id enrichment and is called from ~85 sites across
// protocols/selfservice), so unlike errorBody/authzErrorBody it can't
// look up the request's trace ID — it stays on the plain envelope.
// Widening the Deps interface to thread ctx through is out of scope
// here; see errorBody (interfaces/sso/handlers.go) and authzErrorBody
// (server_discovery.go) for the trace-id-enriched equivalents.
func (s *Server) ErrorBody(errCode string) map[string]any {
	result := make(map[string]any)
	for k, v := range core.ErrorBody(errCode) {
		result[k] = v
	}
	return result
}

func (s *Server) ErrorBodyDesc(errCode, desc string) map[string]any {
	result := make(map[string]any)
	for k, v := range core.ErrorBodyDesc(errCode, desc) {
		result[k] = v
	}
	return result
}

// handleMyEmailChange delegates to selfservice.HandleMyEmailChange.
func (s *Server) handleMyEmailChange(ctx HandlerContext) {
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	selfservice.HandleMyEmailChange(s, ctx, userID)
}

// handleMyEmailVerify delegates to selfservice.HandleMyEmailVerify.
func (s *Server) handleMyEmailVerify(ctx HandlerContext) {
	userID, ok := s.meSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	selfservice.HandleMyEmailVerify(s, ctx, userID)
}

// EmailChangeSender returns the email change sender.
func (s *Server) EmailChangeSender() spi.EmailChangeSender {
	return s.emailChangeSender
}

// EmailVerificationStore returns the email verification store.
func (s *Server) EmailVerificationStore() core.EmailVerificationStore {
	return s.emailVerificationStore
}

// EmailVerificationSender returns the email verification sender.
func (s *Server) EmailVerificationSender() spi.EmailVerificationSender {
	return s.emailVerificationSender
}

// SignupRequiresVerification returns whether mandatory email verification is
// enabled for self-service signup.
func (s *Server) SignupRequiresVerification() bool {
	return s.signupRequireVerification
}

// RegistrationGates returns the wired registration abuse-protection gates.
func (s *Server) RegistrationGates() []spi.RegistrationGate {
	return s.registrationGates
}

// SignupRateLimiter returns the optional per-IP rate limiter for self-service
// signup (WithSelfServiceSignupRateLimiter). Nil means no signup-specific
// rate limiting — full backward compatibility.
func (s *Server) SignupRateLimiter() selfservicecore.RateLimiter {
	return s.signupRateLimiter
}

// EmailVerificationTTL returns the email verification token TTL.
func (s *Server) EmailVerificationTTL() time.Duration {
	return s.emailVerificationTTL
}

// PasswordPolicyValidator returns the wired password policy validator, or nil
// if no policy is enforced.
func (s *Server) PasswordPolicyValidator() spi.PasswordPolicyValidator {
	return s.passwordPolicyValidator
}

// WithPasswordPolicy wires a password policy validator that checks proposed
// passwords against operator-configured complexity rules. When nil (the
// default), no policy is enforced — behaviour is byte-identical to a build
// without the feature. The validator is applied in every code path that sets
// a password: self-service signup, POST /me/password, and POST
// /auth/reset-password. All validation failures return the same generic
// error to prevent enumeration of policy internals.
//
// Password HISTORY (PasswordPolicyConfig.MaxHistory) is a separate mechanism
// — see WithPasswordHistoryStore below — since checking reuse needs a
// per-user store keyed by userID, not just the candidate string
// ValidatePassword receives.
func WithPasswordPolicy(v spi.PasswordPolicyValidator) Option {
	return func(srv *Server) { srv.passwordPolicyValidator = v }
}

// PasswordHistoryStore returns the wired password-history store, or nil if
// history is not enforced (WithPasswordHistoryStore).
func (s *Server) PasswordHistoryStore() core.PasswordHistoryStore {
	return s.passwordHistoryStore
}

// WithPasswordHistoryStore wires a store that remembers a user's recent
// passwords so PasswordPolicyConfig.MaxHistory > 0 can reject reuse. Applied
// at both self-service paths that already run PasswordPolicyValidator: POST
// /me/password and POST /auth/reset-password. NOT applied at signup (a brand
// new account has no prior password to check against) or at admin-initiated
// password resets (interfaces/admin, internal/adminuser — a separate,
// non-SPI validation path).
//
// Nil (the default) means no history is enforced — byte-identical to a build
// without this feature. A CheckHistory error fails OPEN (logged, the change
// proceeds): a history-store outage must never lock a user out of changing
// their own password. A Record error after a successful change is likewise
// logged and non-fatal — the change already succeeded.
func WithPasswordHistoryStore(store core.PasswordHistoryStore) Option {
	return func(s *Server) { s.passwordHistoryStore = store }
}

// passwordMaxAgeDays returns the operator-configured
// PasswordPolicyConfig.MaxAgeDays (via WithPasswordPolicy), or 0 when no
// policy validator is wired, or the wired one doesn't expose it
// (spi.PasswordMaxAgeProvider is an OPTIONAL extension — see
// shared/spi/reg_gate.go). 0 is universally "not enforced" for this
// dimension, matching every other zero-value-means-off policy knob on this
// server (e.g. maxSessionsPerUser).
func (s *Server) passwordMaxAgeDays() int {
	if p, ok := s.passwordPolicyValidator.(spi.PasswordMaxAgeProvider); ok {
		return p.PasswordMaxAgeDays()
	}
	return 0
}

// handleForgotPassword delegates to selfservice.HandleForgotPassword.
func (s *Server) handleForgotPassword(ctx HandlerContext) {
	selfservice.HandleForgotPassword(s, ctx)
}

// handleResetPassword delegates to selfservice.HandleResetPassword.
func (s *Server) handleResetPassword(ctx HandlerContext) {
	selfservice.HandleResetPassword(s, ctx)
}

// handleMyDataExport delegates to selfservice.HandleMyDataExport.
func (s *Server) handleMyDataExport(ctx HandlerContext) {
	selfservice.HandleMyDataExport(s, ctx)
}

// handleMyAccountErase delegates to selfservice.HandleMyAccountErase.
func (s *Server) handleMyAccountErase(ctx HandlerContext) {
	selfservice.HandleMyAccountErase(s, ctx)
}

// --- First-run setup wizard (public, single-use) ---

// PathSetupStatus / PathSetup are the public first-run setup-wizard endpoints.
// Both self-gate on setupWizardFS: when the wizard is not wired
// (setup_wizard.enabled=false) they 404, so a deployment that never opts in
// exposes no setup surface at all.
const (
	PathSetupStatus = "/api/v1/setup/status" // GET, public
	PathSetup       = "/api/v1/setup"        // POST, public, single-use
)

// setupAdminRoleCode / setupAdminClientID mirror the built-in bootstrap
// defaults (platform/bootstrap/builtin) so a wizard-created admin is
// indistinguishable from a config-seeded one: the sso-admin role carries
// admin:* and is assigned under the empty client id that empty-aud admin
// tokens present. setupMinPasswordLen is the floor the wizard also enforces
// client-side.
const (
	setupAdminRoleCode  = "sso-admin"
	setupAdminClientID  = ""
	setupMinPasswordLen = 8
	// errSetupAlreadyInitialized locks the wizard once an admin exists so it
	// can never be replayed to plant a second/rogue admin. errSetupDisabled is
	// the 404 body when the wizard was never enabled.
	errSetupAlreadyInitialized = "already_initialized"
	errSetupDisabled           = "not_found"
)

// setupWizardOn reports whether the first-run wizard is wired
// (setup_wizard.enabled). The setup endpoints self-gate on it.
func (s *Server) setupWizardOn() bool { return s.setupWizardEnabled }

// setupInitialized reports whether first-run setup is complete — i.e. an admin
// already exists. It prefers the sso-admin role assignment (few rows) and
// falls back to any-user-exists when no permissions provider is wired. Also
// true when config/bootstrap seeded an admin, so "config has data -> straight
// into the system, no wizard" falls out for free.
func (s *Server) setupInitialized(ctx context.Context) bool {
	if s.permissions != nil {
		if as, err := s.permissions.ListAssignments(ctx, setupAdminClientID); err == nil {
			for _, a := range as {
				if slices.Contains(a.Roles, setupAdminRoleCode) {
					return true
				}
			}
		}
	}
	if s.userProvider != nil {
		if us, err := s.userProvider.List(ctx); err == nil && len(us) > 0 {
			return true
		}
	}
	return false
}

// handleSetupStatus serves GET /api/v1/setup/status — a public boolean probe
// the admin console loads to decide whether to bounce to /setup/. Returns only
// {initialized, setup_required} (no detail — anti-enumeration). 404s when the
// wizard is disabled, so the console's redirect check is a no-op there.
func (s *Server) handleSetupStatus(ctx HandlerContext) {
	if !s.setupWizardOn() {
		ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: errSetupDisabled})
		return
	}
	done := s.setupInitialized(ctx.Request().Context())
	ctx.JSON(http.StatusOK, map[string]any{"initialized": done, "setup_required": !done})
}

// setupRequest is the first-run wizard payload: the required first admin plus
// an optional first application. Branding/issuer are server-config concerns
// (server.issuer, tenant branding) and are intentionally not runtime-settable
// here.
type setupRequest struct {
	Admin struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"admin"`
	Application *struct {
		Name         string   `json:"name"`
		RedirectURIs []string `json:"redirect_uris"`
	} `json:"application"`
}

// handleSetup serves POST /api/v1/setup — the first-run provisioning call.
// Public but SINGLE-USE: it creates the first admin (and an optional first
// application), then locks — any later call 409s once an admin exists, so it
// can never be replayed to plant a second admin. 404s when the wizard is off.
func (s *Server) handleSetup(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if !s.setupWizardOn() {
		ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: errSetupDisabled})
		return
	}
	reqCtx := ctx.Request().Context()
	if s.setupInitialized(reqCtx) {
		ctx.JSON(http.StatusConflict, map[string]string{core.KeyError: errSetupAlreadyInitialized})
		return
	}
	var req setupRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	if req.Admin.Username == "" || len(req.Admin.Password) < setupMinPasswordLen {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	if err := s.provisionFirstAdmin(reqCtx, req.Admin.Username, req.Admin.Password); err != nil {
		s.logger.Error("setup: provision first admin failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	created := map[string]any{"admin": req.Admin.Username}
	if req.Application != nil && req.Application.Name != "" {
		if id, secret, err := s.provisionFirstClient(reqCtx, req.Application.Name, req.Application.RedirectURIs); err != nil {
			// The admin is already provisioned; a failed optional app must not
			// fail the whole setup — log and report the admin as created.
			s.logger.Error("setup: provision first application failed", "error", err)
		} else {
			created["application"] = map[string]string{"client_id": id, "client_secret": secret}
		}
	}
	s.logger.Info("first-run setup completed", "admin", req.Admin.Username)
	ctx.JSON(http.StatusOK, map[string]any{"ok": true, "created": created})
}

// provisionFirstAdmin creates the first admin: the sso-admin role (idempotent),
// the user, its password credential, and the role assignment — the same
// sequence platform/bootstrap/builtin seeds, but with an operator-chosen
// password instead of a generated one.
func (s *Server) provisionFirstAdmin(ctx context.Context, username, password string) error {
	if s.permissions == nil || s.userProvider == nil || s.passwordCredentialStore == nil {
		return errors.New("setup: user, permissions and password stores must all be wired")
	}
	if err := s.permissions.AddRole(ctx, setupAdminClientID, permissions.Role{
		Code:        setupAdminRoleCode,
		Name:        "SSO Administrator",
		Description: "Full admin:* scope across the control plane.",
		Permissions: []string{AdminScope},
	}); err != nil && !errors.Is(err, permissions.ErrRoleExists) {
		return err
	}
	if err := s.userProvider.CreateOrUpdate(ctx, &core.User{ID: username, ExternalID: username, Provider: "password"}); err != nil {
		return err
	}
	if err := s.passwordCredentialStore.SetPassword(ctx, username, password); err != nil {
		return err
	}
	return s.permissions.AssignRoles(ctx, username, setupAdminClientID, []string{setupAdminRoleCode})
}

// provisionFirstClient registers the optional first application from the
// wizard: a confidential client with a generated id + secret returned once so
// the wizard can display them. Reuses the crypto-random auth-code helper.
func (s *Server) provisionFirstClient(ctx context.Context, name string, redirectURIs []string) (string, string, error) {
	if s.clientStore == nil {
		return "", "", errors.New("setup: client store not wired")
	}
	id, err := generateAuthCodeBytes()
	if err != nil {
		return "", "", err
	}
	secret, err := generateAuthCodeBytes()
	if err != nil {
		return "", "", err
	}
	c := &core.Client{
		ID:                    id,
		Secret:                secret,
		Name:                  name,
		RedirectURIs:          redirectURIs,
		AllowedScopes:         []string{"openid", "profile", "email"},
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         TokenStrategyJWT,
		Active:                true,
	}
	if err := s.clientStore.Add(ctx, c); err != nil {
		return "", "", err
	}
	return id, secret, nil
}
