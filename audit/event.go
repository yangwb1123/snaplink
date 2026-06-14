package audit

import "time"

// EventType identifies the kind of event being recorded. Custom types are
// allowed — the constants below are the ones the sso package emits itself.
type EventType string

const (
	EventLogin           EventType = "login"
	EventLoginFailure    EventType = "login_failure"
	EventLogout          EventType = "logout"
	EventTokenIssued     EventType = "token_issued"
	EventTokenRevoked    EventType = "token_revoked"
	EventCodeSent        EventType = "code_sent"
	EventCallbackFailure EventType = "callback_failure"
	EventClientAccess    EventType = "client_access"
	EventPermissionQuery EventType = "permission_query"

	// EventClientRegistered / EventClientUpdated / EventClientDeleted —
	// DCR (RFC 7591/7592) lifecycle events. Outcome=success on the happy
	// path; ClientID carries the registered client_id.
	EventClientRegistered EventType = "client_registered"
	EventClientUpdated    EventType = "client_updated"
	EventClientDeleted    EventType = "client_deleted"

	EventNetPolicyApply  EventType = "netpolicy_apply"
	EventNetPolicyDelete EventType = "netpolicy_delete"

	// EventLogoutNotified — OIDC Back-Channel Logout 1.0
	// notification attempt. Outcome=success when the RP returned
	// 2xx; Outcome=failure when the POST failed or the RP returned
	// non-2xx. Metadata carries the target URI + (on failure) the
	// reason string.
	EventLogoutNotified EventType = "logout_notified"

	// EventPartialRevokeFailure — at least one TokenIssuer's Revoke
	// returned an error during a bulk revoke (e.g. /token/revoke-all
	// or backchannel logout) while at least one other issuer
	// succeeded. The presented bearer keeps working at the failed
	// issuer until natural expiry, so this MUST page someone or
	// trigger SIEM follow-up — the "logout everywhere" semantic
	// the endpoint promises has been partially violated. Metadata
	// carries `revoked` (succeeded issuer names) + `failed` (failing
	// names) so operators can scope the manual remediation.
	EventPartialRevokeFailure EventType = "partial_revoke_failure"

	// EventTenantTokensRevoked — a tenant suspension actively purged the
	// refresh tokens of every client in the tenant (the proactive
	// companion to the lazy WithTenantSuspensionCheck, which only rejects
	// on the next validate). Outcome=success; ActorID is the tenant ID;
	// Metadata "refresh_tokens_revoked" carries the count killed. Emitted
	// even on a zero count so a SIEM sees the suspension was enforced.
	EventTenantTokensRevoked EventType = "tenant_tokens_revoked"

	// EventAccountLocked — per-account lockout engaged or
	// attempted-against-when-locked. Outcome=failure. ActorID
	// is the lockout key (clientID:identifier so SIEMs can pivot
	// on either dimension). Metadata "until" carries the
	// auto-unlock time.
	EventAccountLocked EventType = "account_locked"

	// EventMFARequired — /auth/login's RiskScorer returned
	// DecisionRequireMFA and the server issued a pending challenge
	// instead of tokens. Outcome=success (the primary credential
	// validated cleanly; the user just hasn't completed step-up yet).
	// ActorID = subject; Metadata "mfa_challenge_id" carries the
	// issued challenge identifier so SIEMs can correlate the followup.
	EventMFARequired EventType = "mfa_required"

	// EventMFASuccess — /auth/mfa accepted the supplied factor.
	// Outcome=success; Metadata "mfa_method" carries the verified
	// method name. Followed by the standard login_success event
	// once the resumed handler mints tokens.
	EventMFASuccess EventType = "mfa_success"

	// EventMFAFailure — /auth/mfa rejected the supplied factor
	// (wrong code / unknown challenge / unsupported method — all
	// collapsed per the oracle-leak hardening contract). Outcome=failure;
	// Reason carries the operator-side detail; the wire response is
	// always the same mfa_invalid shape.
	EventMFAFailure EventType = "mfa_failure"

	// EventAnomalyDetected — surfaced by an AnomalyDetector running
	// off the request hot path (impossible travel, velocity burst,
	// new device, brute-force shadow). The standard recorder sink
	// writes one event per Anomaly with Reason = anomaly type +
	// Metadata containing severity + score + detector-specific
	// evidence. Outcome is always failure (something to investigate),
	// but the login that triggered it may have succeeded — operators
	// correlate via TraceID.
	EventAnomalyDetected EventType = "anomaly_detected"

	// EventWebAuthnRegistered — a WebAuthn registration ceremony
	// completed and the credential was persisted. Outcome=success;
	// Metadata "aaguid" carries the registered authenticator's AAGUID
	// (the public authenticator-model identifier, NOT a secret) so an
	// operator running an attestation allowlist can curate it. Emitted
	// by the cmd ceremony handler ONLY when an attestation policy is
	// active — without a policy the success path stays byte-identical to
	// a pre-policy build (no new audit event).
	EventWebAuthnRegistered EventType = "webauthn_registered"

	// EventWebAuthnAttestationDenied — a WebAuthn registration was
	// REJECTED by the operator's attestation policy: either the
	// authenticator's AAGUID was not on the allowlist (or was on the
	// denylist), or the credential conveyed no attestation (format "none" —
	// a downgrade an active policy refuses). The credential was NOT
	// persisted. Outcome=failure; Metadata "aaguid" carries the rejected
	// AAGUID, "policy_mode" the gating mode (allowlist|denylist), and
	// "reason" a machine-readable cause (aaguid_not_permitted |
	// attestation_format_none); Reason is the human-readable operator-side
	// detail. The registering client only sees a generic attestation_denied
	// error — the specifics live here.
	EventWebAuthnAttestationDenied EventType = "webauthn_attestation_denied"

	// EventTOTPEnrolled — a user completed self-service TOTP enrollment
	// (POST /me/mfa/totp/confirm proved possession of the new secret).
	// Outcome=success; ActorID = the subject; Metadata "factor_id" carries
	// the new factor's opaque handle. The secret itself is NEVER recorded.
	EventTOTPEnrolled EventType = "mfa_totp_enrolled"

	// EventTOTPEnrollFailed — a self-service TOTP enrollment confirm was
	// rejected (wrong code or malformed secret). Outcome=failure; ActorID =
	// the subject; Metadata "reason" carries the operator-side cause while the
	// caller only ever sees the single oracle-safe totp_invalid_code response.
	EventTOTPEnrollFailed EventType = "mfa_totp_enroll_failed"

	// Admin control-plane mutations. Every mutating RPC on the
	// ClientAdmin / UserAdmin / TokenAdmin / PermissionAdmin services emits
	// one of these. ActorID is the admin who issued the call; Reason
	// carries "target=<resource>" for easy auditing.
	EventAdminClientCreated       EventType = "admin_client_created"
	EventAdminClientUpdated       EventType = "admin_client_updated"
	EventAdminClientDeleted       EventType = "admin_client_deleted"
	EventAdminClientSecretRotated EventType = "admin_client_secret_rotated"
	EventAdminUserCreated         EventType = "admin_user_created"
	EventAdminUserUpdated         EventType = "admin_user_updated"
	EventAdminUserDeleted         EventType = "admin_user_deleted"
	EventAdminTokenRevoked        EventType = "admin_token_revoked"
	EventAdminTempTokenIssued     EventType = "admin_temp_token_issued"
	EventAdminRoleAdded           EventType = "admin_role_added"
	EventAdminRoleUpdated         EventType = "admin_role_updated"
	EventAdminRoleRemoved         EventType = "admin_role_removed"
	EventAdminRoleAssigned        EventType = "admin_role_assigned"
	EventAdminRoleUnassigned      EventType = "admin_role_unassigned"
	EventAdminMenusUpdated        EventType = "admin_menus_updated"
	EventAdminTenantCreated       EventType = "admin_tenant_created"
	EventAdminTenantUpdated       EventType = "admin_tenant_updated"
	EventAdminTenantDeleted       EventType = "admin_tenant_deleted"
	EventAdminTenantStatusChanged EventType = "admin_tenant_status_changed"
	EventAdminDomainCreated       EventType = "admin_domain_created"
	EventAdminDomainUpdated       EventType = "admin_domain_updated"
	EventAdminDomainDeleted       EventType = "admin_domain_deleted"
	EventAdminSubjectExported     EventType = "admin_subject_exported"
	EventAdminSubjectErased       EventType = "admin_subject_erased"

	// Bootstrap framework events — one per Step run/skip on first boot
	// (or whenever a new Step is added later).
	EventBootstrapStepApplied EventType = "bootstrap_step_applied"
	EventBootstrapStepSkipped EventType = "bootstrap_step_skipped"
	EventBootstrapStepFailed  EventType = "bootstrap_step_failed"

	// Bootstrap distributed-lock events — multi-replica coordination.
	// Acquired/Released are the happy path; Lost fires when the lease
	// renewal failed mid-run; Contended fires when TryAcquire returned
	// ErrLocked (another replica already holds the slot).
	EventBootstrapLockAcquired  EventType = "bootstrap_lock_acquired"
	EventBootstrapLockReleased  EventType = "bootstrap_lock_released"
	EventBootstrapLockLost      EventType = "bootstrap_lock_lost"
	EventBootstrapLockContended EventType = "bootstrap_lock_contended"

	// Snapshot lifecycle — admin-plane export/restore/delete on the
	// snapshot.Snapshotter / Restorer / Storage. Reason carries the
	// snapshot id + restore mode + per-category counts so auditors can
	// reconstruct the blast radius without replaying the snapshot.
	EventSnapshotExported EventType = "snapshot_exported"
	EventSnapshotRestored EventType = "snapshot_restored"
	EventSnapshotDeleted  EventType = "snapshot_deleted"

	// Release lifecycle — Phase D-3 admin-app pin / rollback. Reason
	// carries the release id + (for pin/rollback) the previous current
	// id so auditors can reconstruct the deploy timeline.
	EventReleaseRegistered EventType = "release_registered"
	EventReleasePinned     EventType = "release_pinned"
	EventReleaseRolledBack EventType = "release_rolled_back"
	EventReleaseDeleted    EventType = "release_deleted"

	// Signing-key rotation. Emitted by the automatic rotation scheduler
	// on each rotation. Reason carries "from=<oldKID> to=<newKID>" so
	// SOC2-style reviews can reconstruct the key timeline (which key was
	// active when, and when the previous one stopped signing).
	EventSigningKeyRotated EventType = "signing_key_rotated"

	// EventSigningKeyAggregationDegraded / EventSigningKeyAggregationRecovered
	// bracket a stall in the leaderless signing-key aggregation subscriber.
	// Degraded (Outcome=failure) fires ONCE per transition when the registry's
	// Subscribe channel closes while the run context is still live — at that
	// point the replica stops adopting peers' newly-rotated keys (peers' tokens
	// will later fail with "unknown kid") even though local signing keeps
	// working, so it MUST page someone. Metadata "reason" carries the operator
	// detail (e.g. "subscribe_channel_closed"). Recovered (Outcome=success)
	// fires once when a resubscribe succeeds and adoption resumes. These are
	// INTERNAL audit events, not a wire error code.
	EventSigningKeyAggregationDegraded  EventType = "signing_key_aggregation_degraded"
	EventSigningKeyAggregationRecovered EventType = "signing_key_aggregation_recovered"

	// OAuth/OIDC token lifecycle beyond the legacy EventTokenIssued.
	// Refresh + ID Token + device-flow events let SIEMs build per-grant
	// dashboards (how often is refresh rotating? are device flows being
	// approved or denied at the consent step?) without parsing reason
	// strings out of generic token_issued records.
	//
	// EventRefreshTokenIssued fires at the three injection sites:
	// /auth/login direct mint, authorization_code exchange, and
	// refresh_token rotation. Metadata carries "rotation=true" on the
	// rotation path so analysts can separate first-issue from rotation.
	EventRefreshTokenIssued EventType = "refresh_token_issued"
	// EventIDTokenIssued fires whenever an id_token is appended to the
	// response (login + authz_code + device flows that requested the
	// openid scope). Separate from EventTokenIssued because operators
	// commonly want a "OIDC adoption" metric distinct from raw token
	// volume.
	EventIDTokenIssued EventType = "id_token_issued"
	// EventDeviceCodeIssued fires on POST /device/code — the start of
	// a device authorization grant.
	EventDeviceCodeIssued EventType = "device_code_issued"
	// EventDeviceCodeApproved fires when a signed-in user POSTs
	// /device/verify with approve=true. ActorID is the user who
	// approved; Metadata carries device_client_id.
	EventDeviceCodeApproved EventType = "device_code_approved"
	// EventDeviceCodeDenied fires on the explicit deny path. Same
	// metadata as Approved.
	EventDeviceCodeDenied EventType = "device_code_denied"

	// EventCIBAAuthRequest fires when POST /backchannel-authentication
	// accepts a poll-mode CIBA request and issues an auth_req_id.
	// Outcome=success; ActorID = resolved subject; Metadata carries
	// client_id + auth_req_id so SIEMs can correlate the followup poll.
	EventCIBAAuthRequest EventType = "ciba_auth_request"
	// EventCIBAApproved fires when the CIBA token poll mints tokens
	// against an approved request. ActorID = subject; Metadata carries
	// client_id.
	EventCIBAApproved EventType = "ciba_approved"
	// EventCIBADenied fires when the CIBA token poll observes a denied
	// request (or the request expired before approval). Outcome=failure;
	// ActorID = subject; Metadata carries client_id.
	EventCIBADenied EventType = "ciba_denied"

	// EventCIBAPingFailed fires when the detached post-resolution ping
	// notifier fails to deliver — either CIBAPingNotifier.Notify returned an
	// error or it PANICKED (a custom notifier bug the supervising goroutine
	// recovered from instead of crashing). Outcome=failure; ClientID set;
	// Metadata carries auth_req_id + a "reason" detail. The ping is
	// best-effort (the client can still poll), so this is operator
	// visibility, NOT a wire error code: it surfaces which client's
	// notification endpoint is wedged/unreachable so a SIEM can act before
	// users notice their backchannel clients silently fell back to poll.
	EventCIBAPingFailed EventType = "ciba_ping_failed"

	// EventRefreshTokenReuse fires when the rotation grant detects a
	// presented-after-rotation refresh token (OAuth Security BCP §4.13)
	// AND the store implements oauth.RefreshTokenFamilyTracker. Reason
	// carries the family id; Metadata carries "killed=<n>" with the
	// count of active descendants invalidated by the family revocation.
	// Outcome is OutcomeFailure — a reuse event is always a security
	// signal, never a happy-path operation.
	EventRefreshTokenReuse EventType = "refresh_token_reuse_detected"

	// EventPasswordWeak / EventPasswordCompromised — non-blocking
	// login-time credential-health signals emitted AFTER a successful
	// password verify (this server only sees plaintext at login, since
	// credentials are pre-bcrypted + seeded). Outcome=success: the login
	// DID succeed and was NOT blocked; these are informational signals for
	// operators to drive a "rotate your password" nudge out of band.
	// ActorID = subject; ClientID set; Metadata "reason" carries the
	// operator-facing detail (e.g. which dictionary matched). Weak fires
	// on a strength heuristic (dictionary match); Compromised fires when a
	// checker reports the credential appears in a breach corpus.
	EventPasswordWeak        EventType = "password_weak"
	EventPasswordCompromised EventType = "password_compromised"

	// EventSPIFFEJWTSVIDAccepted fires when a SPIFFE JWT-SVID was
	// successfully validated and accepted as a token-exchange
	// subject_token, minting this server's token for the mapped mesh
	// workload. Outcome=success; ActorID is the spiffe:// id; ClientID is
	// the exchanging (downstream) client; Metadata carries
	// spiffe_trust_domain / spiffe_namespace / spiffe_service_account.
	// This is an INTERNAL audit event, NOT a wire error code — SVID
	// REJECTIONS are deliberately NOT audited per-cause here (they collapse
	// to one invalid_grant; surfacing the cause would re-introduce the
	// oracle the wire response is hardened against).
	EventSPIFFEJWTSVIDAccepted EventType = "spiffe_jwt_svid_accepted"

	// EventFAPIComplianceViolation fires when the FAPI 2.0 profile
	// (inspection or enforce mode) detects a baseline rule violation.
	// Reason carries the rule id (e.g. "fapi:par_required"); Metadata
	// carries "fapi_rule" + "fapi_detail" + "fapi_mode". Outcome is
	// OutcomeFailure — a violation is always a compliance signal. In
	// inspection mode the request still proceeds; the event is the
	// operator's per-RP compliance-gap signal.
	EventFAPIComplianceViolation EventType = "fapi_compliance_violation"

	// EventRefreshRotationVelocityExceeded fires when the per-family
	// rotation velocity cap is exceeded. Outcome=failure. ClientID + Reason
	// carry the family id; Metadata carries "count" + "killed" (number of
	// active family members invalidated). Wire effect: DeleteFamily →
	// invalid_grant (oracle-safe, same shape as family reuse).
	EventRefreshRotationVelocityExceeded EventType = "refresh_rotation_velocity_exceeded"

	// EventSigningKeyRotationCoordinated fires when a coordinated key-rotation
	// cutover message is published (broadcaster) or adopted (peer) over the
	// cluster Bus. Outcome=success; Metadata carries "outcome" discriminating
	// "deferred", "extended", "adopted_only", or "noop".
	EventSigningKeyRotationCoordinated EventType = "signing_key_rotation_coordinated"

	// EventNativeSSOExchange — OpenID Connect Native SSO 1.0 §3.2: a second
	// native app exchanged an id_token + device_secret for its own tokens.
	// Outcome=success; ActorID=subject; ClientID=requesting client; Metadata
	// "original_client" carries the device_secret's originating client.
	EventNativeSSOExchange EventType = "native_sso_exchange"

	// EventNativeSSOExchangeFailure — a device-secret exchange was rejected.
	// The cause (ds_hash mismatch, consumed/unknown secret, binding mismatch)
	// is in Reason for SIEM use; the WIRE response is always invalid_grant
	// (oracle-safe — no cause leaks externally).
	EventNativeSSOExchangeFailure EventType = "native_sso_exchange_failure"
)

// Outcome distinguishes successful events from attempted/failed ones.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// Event is a single immutable audit record. ID is assigned by the Sink on
// Record; callers leave it empty.
//
// Sensitive fields (raw token bodies, password material) MUST NOT be put on
// an Event. Use TokenID for a hash/prefix that's safe to store.
type Event struct {
	ID           string    `json:"id"`
	Type         EventType `json:"type"`
	Outcome      Outcome   `json:"outcome"`
	Timestamp    time.Time `json:"timestamp"`
	RequestID    string    `json:"request_id,omitempty"`
	TraceID      string    `json:"trace_id,omitempty"`
	SpanID       string    `json:"span_id,omitempty"`
	ParentSpanID string    `json:"parent_span_id,omitempty"`
	ActorID      string    `json:"actor_id,omitempty"`
	ActorIP      string    `json:"actor_ip,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	ClientID     string    `json:"client_id,omitempty"`
	// TenantID is a first-class indexed field for per-tenant metering and
	// querying. Populated by EnrichTenant when the tenant middleware ran;
	// empty for requests outside a tenant context. Mirrors the "tenant.id"
	// Metadata key but promotes it out of the JSON blob so the SQLite sink
	// can index and aggregate efficiently without per-event JSON scanning.
	TenantID      string            `json:"tenant_id,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	TokenStrategy string            `json:"token_strategy,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	TokenID       string            `json:"token_id,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`

	// PrevHash + Hash form a tamper-evident chain when a Recorder
	// is constructed with [WithHashChain]. PrevHash is the previous
	// event's Hash; Hash is sha256(canonical-JSON of this event with
	// Hash cleared). VerifyChain walks a sequence and reports any
	// break. Empty for both = chain disabled.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}
