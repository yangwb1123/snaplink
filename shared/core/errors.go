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

	// ErrQuotaExceeded is returned by TenantQuotaStore.IncrementUsage
	// when the operation would exceed the tenant's configured resource
	// limit. The caller converts this to an appropriate HTTP/gRPC error
	// (e.g. 403 Forbidden for admin API, invalid_request for token).
	ErrQuotaExceeded = errors.New("sso: tenant resource quota exceeded")
	// ErrInvalidQuotaOperation is returned when a quota-store call has an
	// empty tenant, an unknown resource, a non-positive delta, or an invalid
	// quota. It is an internal SPI sentinel, not a wire error code.
	ErrInvalidQuotaOperation = errors.New("sso: invalid tenant quota operation")
	// ErrQuotaRevisionConflict reports a failed compare-and-swap on a
	// versioned quota projection or an absolute usage reconciliation. Callers
	// must refresh the current revision/generation before retrying.
	ErrQuotaRevisionConflict = errors.New("sso: tenant quota revision conflict")

	// ErrPasswordMismatch is returned by PasswordCredentialStore.VerifyPassword
	// when the supplied password does not match the stored hash OR no
	// credential exists for the user. Callers MUST NOT distinguish the two
	// (anti-enumeration); the store runs a cost-matched dummy compare on the
	// unknown-user path for timing parity.
	ErrPasswordMismatch = errors.New("sso: password mismatch")

	// Break-glass admin session sentinels (BreakGlassStore). Self-approval
	// and not-pending are enforced IN the store so the invariant holds for
	// every caller, not just the HTTP handlers that also pre-check.
	ErrAdminSessionNotFound     = errors.New("sso: admin session not found")
	ErrAdminSessionNotPending   = errors.New("sso: admin session is not pending approval")
	ErrAdminSessionSelfApproval = errors.New("sso: admin session approver must differ from creator")
	// ErrAdminSessionNotActive is returned by BreakGlassStore.AttachImpersonationToken
	// when the grant is not active (pending / expired / revoked) — a token must
	// never be minted (or kept) against a grant outside its live window.
	ErrAdminSessionNotActive = errors.New("sso: admin session is not active")

	// ErrCeremonySessionInvalid is a sentinel an Authenticator's Authenticate
	// MAY wrap (fmt.Errorf("...: %w", core.ErrCeremonySessionInvalid)) to
	// signal that the credential failure is a STATEFUL CEREMONY problem — an
	// unknown/expired challenge session, or the identity resolved from it
	// vanishing mid-ceremony — rather than a plain wrong credential. The
	// generic /auth/login failure path (handleAuthFailure) collapses this the
	// SAME oracle-safe way the authenticator's OWN ceremony endpoints do (e.g.
	// WebAuthn's 404 session_invalid) instead of the default 401
	// invalid_credentials, so a client can't distinguish "unknown session"
	// from "unknown user" by response shape, NOR distinguish reaching that
	// state via /auth/login from reaching it via the ceremony's own endpoint.
	ErrCeremonySessionInvalid = errors.New("sso: authentication ceremony session invalid or expired")
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
	// ErrQuotaExceededCode is the wire-format code returned when a tenant's
	// per-resource quota (sessions + clients) is reached. It is a governance
	// code, NOT a credential oracle (same doctrine as region_not_allowed) — it
	// only surfaces on tenant-scoped resource creation, never on a credential
	// check. Distinct from the ErrQuotaExceeded Go sentinel above.
	ErrQuotaExceededCode      = "quota_exceeded"
	ErrNoTokenStrategy        = "no_token_strategy"
	ErrNetPolicyNotConfigured = "netpolicy_not_configured"
	ErrNetPolicyNotFound      = "netpolicy_not_found"
	ErrRiskDenied             = "risk_denied"
	// ErrConditionalAccessDenied is returned (403) when the zero-trust
	// conditional-access (CAP) engine is wired with live enforcement
	// (ConditionalAccessConfig.Enforce) and a matched policy's Decision.Verdict
	// is VerdictDeny. Distinct from ErrRiskDenied (a different, independently
	// optional gate) so audit/SIEM can tell which subsystem refused the login.
	ErrConditionalAccessDenied = "conditional_access_denied"
	ErrPayloadTooLarge         = "payload_too_large"
	// ErrServiceDegraded is returned (503) by the degraded-service gate when the
	// active DR mode refuses a request class (read_only write, non-auth-plane
	// request in auth_only, remote-dependent call in local_only, any non-probe
	// request in maintenance). Carries a Retry-After hint.
	ErrServiceDegraded = "service_degraded"
	// ErrInvalidMode is returned (400) by POST /api/v1/admin/dr/mode when the
	// requested degraded-service mode is not one of the defined values.
	ErrInvalidMode          = "invalid_mode"
	ErrSAMLAssertionInvalid = "saml_assertion_invalid"
	ErrSAMLRequestInvalid   = "saml_request_invalid"
	ErrSAMLNotConfigured    = "saml_not_configured"
	ErrSAMLAssertionFailed  = "saml_assertion_failed"
	ErrMFARequired          = "mfa_required"
	ErrMFAInvalid           = "mfa_invalid"
	ErrResetInvalid         = "reset_invalid"
	ErrConfirmationRequired = "confirmation_required"
	ErrEmailChangeInvalid   = "email_change_invalid"
	ErrAccountExists        = "account_exists"
	ErrVerificationInvalid  = "verification_invalid"
	ErrEmailNotVerified     = "email_not_verified"
	// ErrPasswordExpired is returned (403) when PasswordPolicyConfig.MaxAgeDays
	// is set and the authenticated user's password credential has aged past
	// that window. Distinct from ErrInvalidCredentials/invalid_grant on
	// purpose: by the time this fires the password has ALREADY verified
	// correctly (same ordering as ErrEmailNotVerified/ErrAccountLocked) — this
	// discloses a POLICY STATE the client must react to (route the user
	// through a forced change-password flow), not a credential-validity
	// oracle. An attacker without the correct password never reaches this
	// check, so a distinct code here leaks nothing about whether a guessed
	// password was ever valid. See AGENTS.md §3 Anti-Enumeration.
	ErrPasswordExpired            = "password_expired"
	ErrAuthHookRejected           = "hook_rejected"
	ErrAuthHookTimeout            = "hook_timeout"
	ErrProfileIncomplete          = "profile_incomplete"
	ErrInvitationInvalid          = "invitation_invalid"
	ErrTOTPInvalidCode            = "totp_invalid_code"
	ErrTOTPEnrollmentNotSupported = "totp_enrollment_not_supported"
	ErrWebAuthnRegistration       = "webauthn_registration_failed"
	ErrUnauthorizedClient         = "unauthorized_client"
	ErrInvalidGrant               = "invalid_grant"
	ErrInvalidRedirectURI         = "invalid_redirect_uri"
	ErrAuthCodeNotConfigured      = "authorization_code_not_configured"
	ErrUnsupportedResponseType    = "unsupported_response_type"
	ErrRefreshTokenNotConfigured  = "refresh_token_not_configured"
	ErrInvalidScope               = "invalid_scope"
	ErrInsufficientScope          = "insufficient_scope"
	ErrQuotaProjectionConflict    = "quota_revision_conflict"
	ErrQuotaProjectionUnavailable = "quota_projection_unavailable"
	ErrInvalidPKCEMethod          = "invalid_pkce_method"
	ErrPKCERequired               = "pkce_required"
	ErrInvalidTarget              = "invalid_target"
	ErrPARNotConfigured           = "par_not_configured"
	ErrInvalidRequestURI          = "invalid_request_uri"
	ErrDeviceSecretNotConfigured  = "device_secret_not_configured"
	ErrDeviceCodeNotConfigured    = "device_code_not_configured"
	ErrAuthorizationPending       = "authorization_pending"
	ErrSlowDown                   = "slow_down"
	ErrAccessDenied               = "access_denied"
	ErrExpiredToken               = "expired_token"
	ErrCIBANotConfigured          = "ciba_not_configured"
	ErrUnknownUserID              = "unknown_user_id"
	ErrMissingUserCode            = "missing_user_code"
	ErrInvalidUserCode            = "invalid_user_code"
	ErrLoginRequired              = "login_required"
	ErrInteractionRequired        = "interaction_required"
	ErrConsentRequired            = "consent_required"
	ErrAccountSelectionRequired   = "account_selection_required"
	ErrInvalidPassword            = "invalid_password"
	ErrUnmetAuthReqs              = "unmet_authentication_requirements"
	ErrInvalidDPoPProof           = "invalid_dpop_proof"
	ErrUseDPoPNonce               = "use_dpop_nonce"
	ErrResendTooSoon              = "resend_too_soon"
	ErrNotFound                   = "not_found"
	ErrNotSupported               = "not_supported"
	ErrRegistrationDenied         = "registration_denied"
	ErrPasswordPolicyViolation    = "password_policy_violation"
	ErrBreakGlassReasonRequired   = "break_glass_reason_required"
	ErrBreakGlassTTLExceeded      = "break_glass_ttl_exceeded"
	ErrBreakGlassSelfApproval     = "break_glass_self_approval"
	ErrBreakGlassNotPending       = "break_glass_not_pending"
	// Break-glass live-impersonation (POST .../{id}/impersonate).
	// ErrBreakGlassNotImpersonable rejects a readonly-scope grant STRUCTURALLY
	// — no impersonation bearer can ever be minted for it. ErrBreakGlassNotActive
	// rejects a grant outside its live window. ErrBreakGlassNotOwner rejects a
	// caller who is not the grant's designated admin (only that admin may act as
	// the target). ErrImpersonationUnavailable means no token issuer is
	// resolvable to mint the bearer (server misconfiguration).
	ErrBreakGlassNotImpersonable = "break_glass_not_impersonable"
	ErrBreakGlassNotActive       = "break_glass_not_active"
	ErrBreakGlassNotOwner        = "break_glass_not_owner"
	ErrImpersonationUnavailable  = "impersonation_unavailable"
	// ErrBreakGlassTargetPrivileged (403) refuses to create OR impersonate a grant
	// whose TARGET user holds an admin scope. Impersonating an admin would let
	// support act with that admin's OWN boundary — the escalation break-glass must
	// never enable — so a privileged target is a HARD refusal, not a config toggle.
	ErrBreakGlassTargetPrivileged = "break_glass_target_privileged"
	// Credential compromise-response (POST /api/v1/admin/credentials/{type}/compromise).
	ErrCompromiseReasonRequired        = "compromise_reason_required"
	ErrCredentialCompromiseUnsupported = "credential_compromise_unsupported"
	// Bulk-revoke workflow (POST /api/v1/admin/tokens/bulk-revoke) revocation-storm
	// protection. ConfirmationRequired: the batch is large enough to demand an
	// explicit confirm=true. BatchTooLarge: the batch exceeds the hard cap and
	// must be narrowed (a client- or subject-scoped revoke that would wipe more
	// than the storm ceiling). Neither is a credential oracle — the caller is an
	// authenticated admin.
	ErrBulkRevokeConfirmationRequired = "bulk_revoke_confirmation_required"
	ErrBulkRevokeBatchTooLarge        = "bulk_revoke_batch_too_large"
	// User lifecycle state machine (POST /api/v1/admin/users/:id/lifecycle).
	// IllegalLifecycleTransition: the requested target state is not reachable
	// from the account's current state per the legal-transition table.
	// UnknownLifecycleState: the requested `state` is not a recognized value.
	// LifecycleStateConflict (409): the account's state changed between the read
	// and the write — re-read and retry. None are credential oracles (the caller
	// is an authenticated admin).
	ErrIllegalLifecycleTransition = "illegal_lifecycle_transition"
	ErrUnknownLifecycleState      = "unknown_lifecycle_state"
	ErrLifecycleStateConflict     = "lifecycle_state_conflict"
	// ErrIdentityUnlinkLastMethod (409, DELETE /me/identities/:id) refuses to
	// remove a user's LAST remaining linked identity when the account has no
	// other usable authentication method (see domains/identitylink.GuardUnlink)
	// — the "don't let a user lock themselves out" guard. Not a credential
	// oracle: the caller is the authenticated owner of the identity being
	// unlinked.
	ErrIdentityUnlinkLastMethod = "identity_unlink_last_method"
	// Generic webhook egress engine (platform/lifecycle/webhook, opt-in
	// sso.WithWebhookEngine). NotConfigured guards the admin subscription/
	// dead-letter endpoints when no Engine is wired (defensive — the routes
	// are only mounted when one is). SubscriptionNotFound/DeadLetterNotFound
	// are 404s for an unknown id; neither is a credential oracle (the caller
	// is an authenticated admin).
	ErrWebhookNotConfigured        = "webhook_not_configured"
	ErrWebhookSubscriptionNotFound = "webhook_subscription_not_found"
	ErrWebhookDeadLetterNotFound   = "webhook_deadletter_not_found"
	// ErrRebacNotConfigured guards GET /api/v1/admin/rebac/check (the ReBAC
	// relationship-tuple engine's operational-debugging endpoint,
	// platform/lifecycle/rebac, opt-in sso.WithRebacEngine) when no Engine
	// is wired (defensive — the route is only mounted when one is). Not a
	// credential oracle: the caller is an authenticated admin.
	ErrRebacNotConfigured = "rebac_not_configured"
	// ErrWASMAuthzNotConfigured guards POST /api/v1/admin/wasmauthz/check
	// (the pluggable WASM authorization-decision engine's operational-
	// debugging endpoint, platform/lifecycle/wasmauthz, opt-in
	// sso.WithWASMAuthzEngine) when no Engine is wired (defensive — the
	// route is only mounted when one is). Not a credential oracle: the
	// caller is an authenticated admin.
	ErrWASMAuthzNotConfigured = "wasmauthz_not_configured"
	// ErrUserConflict is returned (409) when an admin CRUD operation would create or
	// update a user whose username or email collides with an existing user. It is a
	// governance code (the caller is an authenticated admin), not a credential oracle.
	// Distinct from ErrUserExists (which is the SPI-level sentinel for an existing user
	// at the storage layer) — this is the wire-format error code in the HTTP response.
	ErrUserConflict = "user_conflict"

	// ErrSessionInvalid is the 404 wire code for a stateful authentication-
	// ceremony session that is unknown, expired, or whose resolved identity
	// vanished mid-ceremony (see ErrCeremonySessionInvalid above). Mirrors the
	// WebAuthn ceremony endpoints' existing oracle-safe collapse so the SAME
	// failure renders identically whether reached via /auth/login or a
	// ceremony's own dedicated endpoint.
	ErrSessionInvalid = "session_invalid"
	// ErrPasswordlessRequired (400) is returned by /auth/login when
	// Client.AllowPasswordlessOnly is true and the request named the
	// "password" provider — the client must complete a WebAuthn passkey
	// ceremony (provider=webauthn) instead. Not a credential oracle: it is a
	// per-client POLICY gate evaluated before any credential is read.
	ErrPasswordlessRequired = "passwordless_required"
	// Generic change-approval workflow (POST /api/v1/admin/changes and
	// .../{id}/approve|reject — platform/lifecycle/admingovernance), generalizing the
	// break-glass propose/approve shape beyond emergency-access grants.
	// ErrChangeReasonRequired / ErrChangeActionTypeRequired mirror break-glass's
	// mandatory-reason validation. ErrChangeActionTypeNotAllowed is returned when
	// AdminChangeApprovalConfig.ActionTypes is non-empty and the caller proposed
	// a type outside it. ErrChangeSelfApproval / ErrChangeNotPending are the wire
	// form of admingovernance.ErrChangeSelfApproval / ErrChangeNotPending.
	ErrChangeReasonRequired       = "change_reason_required"
	ErrChangeActionTypeRequired   = "change_action_type_required"
	ErrChangeActionTypeNotAllowed = "change_action_type_not_allowed"
	ErrChangeSelfApproval         = "change_self_approval"
	ErrChangeNotPending           = "change_not_pending"
	// Config apply/rollback (POST /api/v1/admin/config/apply and
	// .../rollback — platform/configaudit, the declared peer-config baseline
	// write path). ErrConfigApplyApprovalRequired is the misoperation barrier:
	// every apply/rollback MUST carry ?approve=true or the request is refused
	// before any state is touched. ErrConfigApplyConflict is the split-brain
	// rejection: the submitted peer snapshot's recomputed digest does not match
	// the caller-supplied fingerprint (stale or mixed-source submission).
	// ErrConfigApplyNoPrevious is returned by rollback when no baseline exists
	// or the latest baseline has no predecessor to restore.
	ErrConfigApplyApprovalRequired = "config_apply_approval_required"
	ErrConfigApplyConflict         = "config_apply_conflict"
	ErrConfigApplyNoPrevious       = "config_apply_no_previous"
	// ErrUnsupportedVersion is returned (400) when a request's Accept-Version
	// header names a version this deployment does not support (see
	// interfaces/middleware.AcceptVersion, ADR-0008). Only checked when
	// WithAPIVersioning configured a non-empty Supported list — an absent
	// header, or an unconfigured server, never emits this code.
	ErrUnsupportedVersion = "unsupported_version"
	// ErrForbidden is the single, generic 403 the delegated org-admin gate
	// (requireTenantAdmin) returns for EVERY authorization failure — tenant
	// absent, caller not a member, or caller a member but not an admin. The three
	// cases MUST be byte-identical on the wire so a caller cannot probe org
	// existence or another org's roster (anti-enumeration). It is NOT a credential
	// oracle: a subject already knows its own memberships via /me/organizations.
	ErrForbidden = "forbidden"
	// ErrNotificationStoreUnavailable is returned when a configured inbox
	// backend cannot safely serve or mutate the authenticated subject's data.
	ErrNotificationStoreUnavailable = "notification_store_unavailable"
	// ErrLastOrgAdmin is the 409 returned when removing or demoting the FINAL
	// admin of an org (including self-removal / self-demotion) — doing so would
	// orphan the org with no one able to administer it.
	ErrLastOrgAdmin = "last_org_admin"
	// ErrInvalidPolicy is returned (400) by PUT /api/v1/admin/threat-policies/:name
	// (domains/threataction.HandleAdminPutPolicy) when the request body decodes
	// fine but is semantically invalid: an unknown Action, a negative
	// RateLimit.Max/PerWindow, or a Conditions.Operator outside "", "eq", "gt",
	// "lt", "exists". Distinct from ErrInvalidRequest (which covers the
	// malformed-JSON case) the same way ErrInvalidMode is distinct from
	// ErrInvalidRequest for POST /api/v1/admin/dr/mode — a generic decode
	// failure vs. a well-formed-but-invalid value. Always paired with an
	// error_description naming the specific violated field.
	ErrInvalidPolicy = "invalid_policy"
	// Back-channel logout failure replay admin API wire codes. Not-found
	// deliberately also covers cross-tenant ids to avoid resource enumeration.
	ErrBCLFailureNotFound  = "bcl_failure_not_found"
	ErrBCLReplayInProgress = "bcl_replay_in_progress"
	ErrBCLDeliveryFailed   = "bcl_delivery_failed"
)
