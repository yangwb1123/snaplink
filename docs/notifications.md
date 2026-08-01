# User Notifications

Snaplink can turn security-relevant audit events into proactive, end-user
notifications without adding latency or failure coupling to authentication and
account operations. Enable it with `notifications.enabled: true`.

## Delivery Model

The audit sink copies eligible events into a bounded queue. Workers resolve the
target subject, apply a per-`{subject,type}` cooldown, consult preferences for
each channel independently, and deliver to the in-app store and optional SMTP
adapter. Email is attempted up to three times. Store, preference, queue, and
email failures are fail-open for the originating operation and are observable
through logs and `sso_notifications_delivery_failed_total`.

The built-in memory store retains at most 1,000 notifications per subject and
opportunistically removes read entries older than 90 days. The SQLite backend
persists inbox entries and preferences. Account erasure deletes both records
and preferences before deleting the user.

## Event Mapping

| Source | Notification type | Default severity |
|---|---|---|
| `new_device_login` | `new_device_login` | warning |
| `device_trust_revoked`, `mfa_removed` | `mfa_removed` | warning |
| `consent_granted`, `consent_revoked` | `consent_granted` | info |
| `password_compromised` | `password_leaked` | critical |
| `password_expiring` | `password_expiring` | warning |
| `password_changed`, `password_reset_completed` | `security_event` | warning |
| `account_locked` | `account_locked` | critical |
| `anomaly_detected`, `refresh_token_reuse`, `admin_role_assigned`, `admin_role_unassigned` | `security_event` | warning |
| `admin_consent_revoked` | `consent_granted` | warning |
| `admin_mfa_factor_removed` | `mfa_removed` | critical |
| `admin_recovery_codes_reset`, `admin_password_reset`, `admin_user_email_changed`, `admin_device_secrets_revoked`, `admin_refresh_tokens_revoked` | `security_event` | warning |
| Active-session expiry scan | `session_expiring` | warning |

Events raised by an administrator are delivered to the affected user, not the
operator: admin APIs attach `target_user` or `target_user_id` metadata and role
assignment uses the same target metadata. Refresh-token reuse records the token
owner as the subject. Because `account_locked` stores a canonical
`client_id:identity` lock key rather than a user ID, the router resolves the
identity through the configured user provider. Unknown or ambiguous identities
are deliberately suppressed instead of writing a notification into another
user's inbox.

The session scanner runs immediately when notification workers start and then
at `notifications.session_scan_interval`. It reads only active sessions from the
wired SessionManager, selects those expiring within
`notifications.session_expiry_warning`, and shares the normal per-subject/type
cooldown so multiple sessions cannot create a notification storm. A backend
that does not support `ListAll` fails open and retries on the next scan.

## Self-Service API

All endpoints require the normal `/me` bearer token and enforce the same tenant
residency checks as other self-service data.

| Method and path | Behavior |
|---|---|
| `GET /me/notifications?limit=20&before_id=...&unread_only=true` | Returns newest-first inbox entries, total unread count, and `has_more`; `limit` is 1–100 |
| `POST /me/notifications/{id}/read` | Idempotently marks an entry owned by the caller as read |
| `GET /me/notifications/preferences` | Returns every supported type/channel pair, defaulting unspecified pairs to enabled |
| `PUT /me/notifications/preferences` | Replaces explicit preferences after validating unique supported type/channel pairs |
| `GET /me/notifications/stream` | Bearer-authenticated SSE stream filtered to the caller's subject; request query parameters cannot widen the filter |

The separate account portal shows a live unread badge, five-entry preview,
paginated inbox, mark-one/mark-all controls, links to the relevant security
surface, and per-type email/in-app switches.

## Preference Semantics

Supported channels are `in_app` and `email`. Supported types are
`password_expiring`, `new_device_login`, `mfa_removed`, `consent_granted`,
`session_expiring`, `password_leaked`, `account_locked`, and `security_event`.
An absent pair defaults to enabled. Disabling every pair suppresses user-facing
delivery but never suppresses the underlying audit event.
