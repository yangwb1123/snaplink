package selfservicecore

import (
	"context"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// RateLimiter is the subset of ratelimit.Limiter that self-service handlers
// need. Defined locally so protocols/selfservice does not depend on
// interfaces/ratelimit (which would violate the layer boundary).
type RateLimiter interface {
	Allow(key string) (ok bool, retryAfter time.Duration)
}

// Retry-After header name, duplicated here to avoid importing interfaces/ratelimit.
const HeaderRetryAfter = "Retry-After"

// Deps defines the dependencies needed for self-service operations.
// *sso.Server satisfies this interface via accessor methods.
type Deps interface {
	// User management
	UserProvider() core.UserProvider
	PasswordCredentialStore() core.PasswordCredentialStore

	// Token stores
	PasswordResetStore() core.PasswordResetStore

	// Configuration
	EmailChangeTTL() time.Duration
	PasswordResetTTL() time.Duration

	// Password reset delivery
	PasswordResetResolver() func(ctx context.Context, identifier string) (string, error)
	PasswordResetDeliveryResolver() func(ctx context.Context, userID string) (string, error)
	PasswordResetSender() spi.PasswordResetSender

	// Email change delivery
	EmailChangeSender() spi.EmailChangeSender
	EmailChangeStore() core.EmailChangeStore

	// Email verification (signup)
	EmailVerificationStore() core.EmailVerificationStore
	EmailVerificationSender() spi.EmailVerificationSender
	SignupRequiresVerification() bool
	EmailVerificationTTL() time.Duration
	RegistrationGates() []spi.RegistrationGate
	SignupRateLimiter() RateLimiter

	// Session management
	SessionManager() core.SessionManager

	// B2B org self-service (GET /me/organizations, DELETE /me/organizations/:tenant_id,
	// POST /me/invitations/accept).
	TenantUserStore() core.TenantUserStore
	InvitationStore() core.InvitationStore

	// Audit and logging
	Auditor() *audit.Recorder
	Logger() spi.Logger

	// Helper methods
	GenerateAuthCodeBytes() (string, error)
	TokenNoStoreHeaders(ctx core.HandlerContext)
	ErrorBody(errCode string) map[string]any

	// Bearer validation for authenticated /me endpoints.
	MeSubjectOrChallenge(ctx core.HandlerContext) (userID string, ok bool)
	// MeClaimsOrChallenge is the full-claims variant of MeSubjectOrChallenge —
	// handlers that need more than the subject (e.g. the current session SID for
	// "sign out of other devices") use it. Writes the oracle-safe 401 challenge
	// on failure.
	MeClaimsOrChallenge(ctx core.HandlerContext) (*core.TokenClaims, bool)

	// Consent self-service (GET /consents/me, DELETE /consents/me/:client_id).
	ConsentStore() core.ConsentStore
	RecordConsentRevoked(ctx core.HandlerContext, userID, clientID string)

	// Profile self-service (GET/PATCH /me).
	ResolveIssuer(ctx core.HandlerContext) string
	SelfEditableAttrs() map[string]struct{}

	// Data-residency gates for the /me/* surface. Both return (code, true) when
	// the request must be denied (caller writes the 403); (_, false) when it may
	// proceed. Zero-cost when residency is not wired (returns "", false).
	//
	// ResidencyGateAccess covers the read paths (GET /me, GET /me/data-export).
	// ResidencyGateWrite covers the write paths (PATCH /me, POST /me/password,
	// TOTP/passkey enroll, email change, account erase).
	ResidencyGateAccess(ctx core.HandlerContext, claims *core.TokenClaims) (code string, denied bool)
	ResidencyGateWrite(ctx core.HandlerContext, claims *core.TokenClaims) (code string, denied bool)

	// WebAuthn passkey self-registration (POST /me/mfa/webauthn/{begin,finish}).
	WebAuthnRegistrar() core.WebAuthnRegistrar

	// MFA factor self-service (GET/DELETE /me/mfa, POST /me/mfa/totp/{begin,confirm}).
	MFAEnrollmentStore() core.MFAEnrollmentStore
	TOTPEnroller() core.TOTPEnroller
	NewMFAFactorID() (string, error)

	// GDPR self-service
	DataExporter() *compliance.Exporter
	AccountEraser() *compliance.Eraser

	// Password policy
	PasswordPolicyValidator() spi.PasswordPolicyValidator
}

// RecordSelfErase emits a subject_self_erased audit event for GDPR Art. 17
// self-service erasure. No-op when no auditor is wired.
func RecordSelfErase(d Deps, ctx core.HandlerContext, userID string, report *compliance.Report) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventSubjectSelfErased,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "dry_run", fmt.Sprintf("%t", report.DryRun))
	audit.SetMeta(evt, "sessions_destroyed", fmt.Sprintf("%d", report.SessionsDestroyed))
	audit.SetMeta(evt, "refresh_tokens_deleted", fmt.Sprintf("%d", report.RefreshTokensDeleted))
	audit.SetMeta(evt, "user_deleted", fmt.Sprintf("%t", report.UserDeleted))
	if err := report.Err(); err != nil {
		evt.Outcome = audit.OutcomeFailure
		evt.Reason = err.Error()
	}
	aud.Record(ctx.Request().Context(), evt)
}
