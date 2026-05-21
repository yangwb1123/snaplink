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

	// EventAccountLocked — per-account lockout engaged or
	// attempted-against-when-locked. Outcome=failure. ActorID
	// is the lockout key (clientID:identifier so SIEMs can pivot
	// on either dimension). Metadata "until" carries the
	// auto-unlock time.
	EventAccountLocked EventType = "account_locked"

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

	// EventRefreshTokenReuse fires when the rotation grant detects a
	// presented-after-rotation refresh token (OAuth Security BCP §4.13)
	// AND the store implements RefreshTokenFamilyTracker. Reason
	// carries the family id; Metadata carries "killed=<n>" with the
	// count of active descendants invalidated by the family revocation.
	// Outcome is OutcomeFailure — a reuse event is always a security
	// signal, never a happy-path operation.
	EventRefreshTokenReuse EventType = "refresh_token_reuse_detected"
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
	ID            string            `json:"id"`
	Type          EventType         `json:"type"`
	Outcome       Outcome           `json:"outcome"`
	Timestamp     time.Time         `json:"timestamp"`
	RequestID     string            `json:"request_id,omitempty"`
	TraceID       string            `json:"trace_id,omitempty"`
	SpanID        string            `json:"span_id,omitempty"`
	ParentSpanID  string            `json:"parent_span_id,omitempty"`
	ActorID       string            `json:"actor_id,omitempty"`
	ActorIP       string            `json:"actor_ip,omitempty"`
	UserAgent     string            `json:"user_agent,omitempty"`
	ClientID      string            `json:"client_id,omitempty"`
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
