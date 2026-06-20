package core

// Stable error code strings returned to API callers.
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
	// Data-residency governance signals (multi-region layer). Like
	// tenant_mismatch (the 403 that reveals a client's tenant binding),
	// these are governance signals, NOT credential oracles: they reveal a
	// tenant's data-residency binding, which the operator already controls,
	// so they carry no anti-enumeration concern. region_not_allowed = the
	// serving region is outside the tenant's AllowedRegions;
	// residency_violation = a write would land outside the residency
	// boundary. Enforcement that returns these is a later layer.
	ErrRegionNotAllowed       = "region_not_allowed"
	ErrResidencyViolation     = "residency_violation"
	ErrNoTokenStrategy        = "no_token_strategy"
	ErrNetPolicyNotConfigured = "netpolicy_not_configured"
	ErrNetPolicyNotFound      = "netpolicy_not_found"
	ErrRiskDenied             = "risk_denied"
	ErrPayloadTooLarge        = "payload_too_large"

	// SAML 2.0 wire codes (cluster: external/forked SAML module). Declared
	// in core so the path/error literals stay centralized (AGENTS.md §8)
	// even though the SAML protocol handlers live in an operator's nested
	// module — the registry seam (cmd samlHandlerRegistry) hands the module
	// these as its canonical error vocabulary so SP/IdP failures map to a
	// stable shape. ErrSAMLAssertionInvalid = a returned assertion fails
	// validation (bad signature, wrong audience/issuer, expired, replayed);
	// ErrSAMLRequestInvalid = a malformed/forged AuthnRequest or relay
	// state; ErrSAMLNotConfigured = a SAML endpoint hit when no handler is
	// wired (cfg.saml.handler empty). The SAML module SHOULD collapse the
	// distinct assertion-validation failure causes onto the single
	// ErrSAMLAssertionInvalid to avoid an oracle (same hardening as the
	// OAuth single-use paths, AGENTS.md §2).
	//
	// ErrSAMLAssertionFailed is the IdP-side INTERNAL failure (500): the
	// server could not MINT/sign an assertion — e.g. the per-tenant signing
	// key can't drive XML-DSig (an Ed25519 issuer; goxmldsig has no EdDSA
	// method) or the signing operation errored. It is DISTINCT from
	// ErrSAMLRequestInvalid (a 400 client/request fault) so an SP can tell
	// "your request was bad" from "the IdP is misconfigured", and the IdP
	// FAILS CLOSED on it (never falls back to another tenant's key).
	ErrSAMLAssertionInvalid = "saml_assertion_invalid"
	ErrSAMLRequestInvalid   = "saml_request_invalid"
	ErrSAMLNotConfigured    = "saml_not_configured"
	ErrSAMLAssertionFailed  = "saml_assertion_failed"

	// MFA orchestration. ErrMFARequired is the pending status returned
	// by /auth/login when the spi.RiskScorer decided RequireMFA and a
	// spi.MFAProvider is wired — the response carries mfa_challenge_id +
	// mfa_methods instead of tokens. ErrMFAInvalid is the single wire
	// response /auth/mfa returns for every failure (unknown / expired /
	// already-consumed challenge, unsupported method, wrong factor) per
	// the oracle-leak hardening contract.
	ErrMFARequired = "mfa_required"
	ErrMFAInvalid  = "mfa_invalid"
	// ErrResetInvalid is the single oracle-safe response for every
	// /auth/reset-password failure (unknown / expired / consumed token, user
	// gone, set-password error) — the cause lives only in the audit event.
	ErrResetInvalid = "reset_invalid"
	// ErrConfirmationRequired is returned by POST /me/account/erase when the
	// confirmation field is missing or does not match the bearer's subject —
	// a guard against accidental / CSRF-driven irreversible self-deletion.
	ErrConfirmationRequired = "confirmation_required"
	// ErrEmailChangeInvalid is the single oracle-safe response for every
	// POST /me/email/verify failure (unknown / expired / consumed token, or a
	// token belonging to a different user) — cause only in the audit event.
	ErrEmailChangeInvalid = "email_change_invalid"
	// ErrAccountExists is returned by POST /auth/register when the chosen
	// username already exists (signup never overwrites an existing account).
	ErrAccountExists = "account_exists"
	// ErrInvitationInvalid is the single oracle-safe response for every
	// POST /me/invitations/accept failure (unknown / expired / consumed token) —
	// cause only in logs. Never reveals whether the token existed.
	ErrInvitationInvalid = "invitation_invalid"
	// ErrTOTPInvalidCode is the single oracle-safe response for every TOTP
	// enrollment-confirm failure (bad base32 secret, wrong/expired code) so a
	// caller cannot tell which input was at fault. ErrTOTPEnrollmentNotSupported
	// is returned when the wired MFAEnrollmentStore is not a TOTPEnrollmentWriter
	// (or no TOTP authenticator is wired for confirm verification).
	ErrTOTPInvalidCode            = "totp_invalid_code"
	ErrTOTPEnrollmentNotSupported = "totp_enrollment_not_supported"
	// ErrWebAuthnRegistration is the generic failure for self-service passkey
	// registration confirm (expired/unknown session, bad attestation, parse
	// error) — the operator-side cause lives in logs/audit, not the wire.
	ErrWebAuthnRegistration      = "webauthn_registration_failed"
	ErrInvalidGrant              = "invalid_grant"
	ErrInvalidRedirectURI        = "invalid_redirect_uri"
	ErrAuthCodeNotConfigured     = "authorization_code_not_configured"
	ErrUnsupportedResponseType   = "unsupported_response_type"
	ErrRefreshTokenNotConfigured = "refresh_token_not_configured"
	ErrInvalidScope              = "invalid_scope"
	ErrInvalidPKCEMethod         = "invalid_pkce_method"
	ErrPKCERequired              = "pkce_required"
	ErrInvalidTarget             = "invalid_target" // RFC 8707 §2
	ErrPARNotConfigured          = "par_not_configured"
	ErrInvalidRequestURI         = "invalid_request_uri" // RFC 9126 §2.2

	// ErrDeviceSecretNotConfigured is returned on /token when the device_sso
	// scope is requested but no DeviceSecretStore is wired (Native SSO 1.0).
	ErrDeviceSecretNotConfigured = "device_secret_not_configured"

	// RFC 8628 device authorization grant errors.
	ErrDeviceCodeNotConfigured = "device_code_not_configured"
	ErrAuthorizationPending    = "authorization_pending"
	ErrSlowDown                = "slow_down"
	ErrAccessDenied            = "access_denied"
	ErrExpiredToken            = "expired_token"

	// OIDC CIBA Core 1.0 backchannel authentication errors.
	// ErrCIBANotConfigured is returned by /backchannel-authentication
	// and grant_type=ciba when the CIBA store / transport are not
	// wired (opt-in via WithCIBA). ErrUnknownUserID is the §13
	// response when no hint resolves to a known user (collapsed for
	// anti-enumeration — see docs/error-codes.md). ErrMissingUserCode
	// is reserved for user-code mode (not implemented; poll mode only).
	ErrCIBANotConfigured = "ciba_not_configured"
	ErrUnknownUserID     = "unknown_user_id"
	ErrMissingUserCode   = "missing_user_code"

	// OIDC Core §3.1.2.6 authentication error responses returned
	// when a prompt parameter constrains the AS's ability to
	// surface the necessary interaction.
	ErrLoginRequired            = "login_required"
	ErrInteractionRequired      = "interaction_required"
	ErrConsentRequired          = "consent_required"
	ErrAccountSelectionRequired = "account_selection_required"

	// ErrInvalidPassword is returned by POST /me/password when the supplied
	// current password does not match. The caller is authenticated as their
	// own account (bearer), so naming the wrong-current-password case is not
	// an enumeration leak — the user needs to know their entry was wrong.
	ErrInvalidPassword = "invalid_password"

	// ErrUnmetAuthReqs is returned on /auth/login when the RP
	// supplied acr_values and the authenticator's AchievedACR is
	// either absent or not in that set.  OIDC Core §3.1.2.6 /
	// §5.5.1.1: the AS MUST return this code when it cannot
	// satisfy the requested Authentication Context Class.
	ErrUnmetAuthReqs = "unmet_authentication_requirements"

	// RFC 9449 §5.2 — invalid_dpop_proof is returned when the
	// `DPoP` header is present but fails verification (bad
	// signature, mismatched htm / htu / iat, replayed jti).
	ErrInvalidDPoPProof = "invalid_dpop_proof"

	// RFC 9449 §8 — use_dpop_nonce signals the client must include
	// a server-issued nonce claim in subsequent DPoP proofs. The
	// fresh nonce is delivered to the client via the `DPoP-Nonce`
	// response header; the client repeats the request with that
	// nonce embedded in the proof JWT's `nonce` claim.
	ErrUseDPoPNonce = "use_dpop_nonce"

	// ErrNotFound is returned when a requested resource does not exist and
	// revealing its existence would be safe (not oracle-leaking). Used by
	// /sessions/me/:id and /consents/me/:client_id.
	ErrNotFound = "not_found"
	// ErrNotSupported is returned for features that are not implemented.
	ErrNotSupported = "not_supported"
)
