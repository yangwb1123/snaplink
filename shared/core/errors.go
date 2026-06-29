package core

import "errors"

// Sentinel errors returned by storage interfaces (ClientStore, UserProvider,
// SessionManager, TokenIssuer). Admin RPCs translate these into the
// appropriate gRPC status codes (NotFound, AlreadyExists, Unimplemented),
// which the gRPC-Gateway then maps to HTTP 404 / 409 / 501.
var (
	ErrClientExists = errors.New("sso: client already exists")
	ErrNoSuchClient = errors.New("sso: client not found")

	ErrUserExists = errors.New("sso: user already exists")
	ErrNoSuchUser = errors.New("sso: user not found")

	ErrSessionNotFound = errors.New("sso: session not found")

	// ErrUnsupportedOperation is returned by token issuers (and any other
	// store) for capabilities the backend cannot honor — e.g. JWT issuers
	// have no notion of "list active tokens" because tokens are stateless.
	// Admin RPCs translate this to gRPC Unimplemented / HTTP 501.
	ErrUnsupportedOperation = errors.New("sso: operation not supported by backend")

	// ErrNoConsentGrant is returned by ConsentStore.GetConsent when no
	// consent record exists for the requested (userID, clientID) pair.
	// The consent gate in /auth/login treats this as "user has never
	// consented" and returns consent_required.
	ErrNoConsentGrant = errors.New("sso: no consent grant found")

	// ErrPasswordMismatch is returned by PasswordCredentialStore.VerifyPassword
	// when the supplied password does not match the stored hash OR no
	// credential exists for the user. Callers MUST NOT distinguish the two
	// (anti-enumeration); the store runs a cost-matched dummy compare on the
	// unknown-user path for timing parity.
	ErrPasswordMismatch = errors.New("sso: password mismatch")
)

// Stable error code strings returned to API callers in JSON error bodies.
// These are distinct from sentinel errors above — sentinels are Go error
// values for store interfaces; these are wire-format strings sent as the
// "error" field in OAuth/OIDC error responses and admin API JSON bodies.
const (
	ErrInvalidRequest            = "invalid_request"
	ErrInvalidCredentials        = "invalid_credentials"
	ErrAccountLocked             = "account_locked"
	ErrInvalidToken              = "invalid_token"
	ErrInvalidClient             = "invalid_client"
	ErrInvalidCallback           = "invalid_callback"
	ErrCallbackFailed            = "callback_failed"
	ErrUnsupportedProvider       = "unsupported_provider"
	ErrUnknownProvider           = "unknown_provider"
	ErrUnsupportedGrantType      = "unsupported_grant_type"
	ErrMissingToken              = "missing_token"
	ErrMissingClientID           = "missing_client_id"
	ErrUserNotFound              = "user_not_found"
	ErrClientNotFound            = "client_not_found"
	ErrInternal                  = "internal_error"
	ErrServerMisconfigured       = "server_misconfigured"
	ErrSessionMgrNotConfigured   = "session_manager_not_configured"
	ErrClientStoreNotConfigured  = "client_store_not_configured"
	ErrSessionIDOrBearerRequired = "session_id_or_bearer_required"
	ErrProviderAndTargetRequired = "provider_and_target_required"
	ErrProviderDoesNotSendCodes  = "provider_does_not_send_codes"
	ErrSendFailed                = "send_failed"
	ErrUnauthorized              = "unauthorized"
	ErrAuthenticatorNotAllowed   = "authenticator_not_allowed_for_client"
	ErrInactiveClient            = "inactive_client"
	ErrTenantMismatch            = "tenant_mismatch"
	ErrRegionNotAllowed          = "region_not_allowed"
	ErrResidencyViolation        = "residency_violation"
	ErrNoTokenStrategy           = "no_token_strategy"
	ErrNetPolicyNotConfigured    = "netpolicy_not_configured"
	ErrNetPolicyNotFound         = "netpolicy_not_found"
	ErrRiskDenied                = "risk_denied"
	ErrPayloadTooLarge           = "payload_too_large"
	ErrSAMLAssertionInvalid      = "saml_assertion_invalid"
	ErrSAMLRequestInvalid        = "saml_request_invalid"
	ErrSAMLNotConfigured         = "saml_not_configured"
	ErrSAMLAssertionFailed       = "saml_assertion_failed"
	ErrMFARequired               = "mfa_required"
	ErrMFAInvalid                = "mfa_invalid"
	ErrResetInvalid              = "reset_invalid"
	ErrConfirmationRequired      = "confirmation_required"
	ErrEmailChangeInvalid        = "email_change_invalid"
	ErrAccountExists             = "account_exists"
	ErrVerificationInvalid       = "verification_invalid"
	ErrEmailNotVerified          = "email_not_verified"
	ErrInvitationInvalid         = "invitation_invalid"
	ErrTOTPInvalidCode           = "totp_invalid_code"
	ErrTOTPEnrollmentNotSupported = "totp_enrollment_not_supported"
	ErrWebAuthnRegistration      = "webauthn_registration_failed"
	ErrUnauthorizedClient        = "unauthorized_client"
	ErrInvalidGrant              = "invalid_grant"
	ErrInvalidRedirectURI        = "invalid_redirect_uri"
	ErrAuthCodeNotConfigured     = "authorization_code_not_configured"
	ErrUnsupportedResponseType   = "unsupported_response_type"
	ErrRefreshTokenNotConfigured = "refresh_token_not_configured"
	ErrInvalidScope              = "invalid_scope"
	ErrInvalidPKCEMethod         = "invalid_pkce_method"
	ErrPKCERequired              = "pkce_required"
	ErrInvalidTarget             = "invalid_target"
	ErrPARNotConfigured          = "par_not_configured"
	ErrInvalidRequestURI         = "invalid_request_uri"
	ErrDeviceSecretNotConfigured = "device_secret_not_configured"
	ErrDeviceCodeNotConfigured   = "device_code_not_configured"
	ErrAuthorizationPending      = "authorization_pending"
	ErrSlowDown                  = "slow_down"
	ErrAccessDenied              = "access_denied"
	ErrExpiredToken              = "expired_token"
	ErrCIBANotConfigured         = "ciba_not_configured"
	ErrUnknownUserID             = "unknown_user_id"
	ErrMissingUserCode           = "missing_user_code"
	ErrLoginRequired             = "login_required"
	ErrInteractionRequired       = "interaction_required"
	ErrConsentRequired           = "consent_required"
	ErrAccountSelectionRequired  = "account_selection_required"
	ErrInvalidPassword           = "invalid_password"
	ErrUnmetAuthReqs             = "unmet_authentication_requirements"
	ErrInvalidDPoPProof          = "invalid_dpop_proof"
	ErrUseDPoPNonce              = "use_dpop_nonce"
	ErrResendTooSoon             = "resend_too_soon"
	ErrNotFound                  = "not_found"
	ErrNotSupported              = "not_supported"
	ErrRegistrationDenied        = "registration_denied"
)
