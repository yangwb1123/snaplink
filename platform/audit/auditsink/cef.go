package auditsink

import (
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

// cefEventNames curates the CEF "Name" (human-readable event title) field
// for every EventType this SDK's own emitters produce, grouped to mirror
// auditspi/event_types*.go so a reviewer can diff the two side by side when
// a new const is added there. An EventType absent from this table — a
// future SDK addition not yet ported here, or an operator's own custom
// type — falls back to humanizeEventType, never to an empty string; see
// cefName. The conformance test in platform/audit/siem_conformance_test.go
// asserts every const currently defined has an explicit entry here.
var cefEventNames = map[auditspi.EventType]string{
	// core auth + token lifecycle
	auditspi.EventLogin:           "User Login",
	auditspi.EventLoginFailure:    "User Login Failure",
	auditspi.EventLogout:          "User Logout",
	auditspi.EventTokenIssued:     "Token Issued",
	auditspi.EventTokenRevoked:    "Token Revoked",
	auditspi.EventCodeSent:        "Verification Code Sent",
	auditspi.EventCallbackFailure: "OAuth Callback Failure",
	auditspi.EventClientAccess:    "Client Access",
	auditspi.EventPermissionQuery: "Permission Query",
	// DCR
	auditspi.EventClientRegistered: "Client Registered",
	auditspi.EventClientUpdated:    "Client Updated",
	auditspi.EventClientDeleted:    "Client Deleted",
	// network policy
	auditspi.EventNetPolicyApply:  "Network Policy Applied",
	auditspi.EventNetPolicyDelete: "Network Policy Deleted",
	// back-channel logout + partial revoke
	auditspi.EventLogoutNotified:       "Back-Channel Logout Notified",
	auditspi.EventPartialRevokeFailure: "Partial Token Revoke Failure",
	// tenant + lockout
	auditspi.EventTenantTokensRevoked:   "Tenant Tokens Revoked",
	auditspi.EventTenantSessionsRevoked: "Tenant Sessions Revoked",
	auditspi.EventAccountLocked:         "Account Locked",
	// MFA + anomaly
	auditspi.EventMFARequired:     "MFA Required",
	auditspi.EventMFASuccess:      "MFA Success",
	auditspi.EventMFAFailure:      "MFA Failure",
	auditspi.EventAnomalyDetected: "Anomaly Detected",
	// webauthn
	auditspi.EventWebAuthnRegistered:        "WebAuthn Credential Registered",
	auditspi.EventWebAuthnAttestationDenied: "WebAuthn Attestation Denied",
	// password reset + TOTP enroll
	auditspi.EventPasswordResetRequested:   "Password Reset Requested",
	auditspi.EventPasswordResetCompleted:   "Password Reset Completed",
	auditspi.EventPasswordResetFailed:      "Password Reset Failed",
	auditspi.EventTOTPEnrolled:             "TOTP Enrolled",
	auditspi.EventTOTPEnrollFailed:         "TOTP Enrollment Failed",
	auditspi.EventRecoveryCodesRegenerated: "MFA Recovery Codes Regenerated",
	// consent
	auditspi.EventConsentGranted: "Consent Granted",
	auditspi.EventConsentRevoked: "Consent Revoked",
	auditspi.EventConsentDenied:  "Consent Denied",
	// self-service + email change
	auditspi.EventSelfRegistered:       "Self-Service Registration",
	auditspi.EventSubjectDataExported:  "Subject Data Exported",
	auditspi.EventSubjectSelfErased:    "Subject Self-Erased",
	auditspi.EventEmailChangeRequested: "Email Change Requested",
	auditspi.EventEmailChanged:         "Email Changed",
	// org membership
	auditspi.EventOrgLeft:                  "Organization Left",
	auditspi.EventOrgMemberAutoProvisioned: "Organization Member Auto-Provisioned",
	auditspi.EventInvitationSent:           "Invitation Sent",
	auditspi.EventInvitationAccepted:       "Invitation Accepted",
	auditspi.EventInvitationRevoked:        "Invitation Revoked",
	// credential health + SPIFFE + FAPI
	auditspi.EventPasswordWeak:            "Weak Password Detected",
	auditspi.EventPasswordCompromised:     "Compromised Password Detected",
	auditspi.EventSPIFFEJWTSVIDAccepted:   "SPIFFE JWT-SVID Accepted",
	auditspi.EventFAPIComplianceViolation: "FAPI Compliance Violation",
	// refresh rotation + token lifecycle
	auditspi.EventRefreshTokenReuse:               "Refresh Token Reuse Detected",
	auditspi.EventRefreshRotationVelocityExceeded: "Refresh Rotation Velocity Exceeded",
	auditspi.EventRefreshTokenIssued:              "Refresh Token Issued",
	auditspi.EventIDTokenIssued:                   "ID Token Issued",
	auditspi.EventDeviceCodeIssued:                "Device Code Issued",
	auditspi.EventDeviceCodeApproved:              "Device Code Approved",
	auditspi.EventDeviceCodeDenied:                "Device Code Denied",
	// CIBA + native SSO
	auditspi.EventCIBAAuthRequest:          "CIBA Authentication Request",
	auditspi.EventCIBAApproved:             "CIBA Approved",
	auditspi.EventCIBADenied:               "CIBA Denied",
	auditspi.EventCIBAPingFailed:           "CIBA Ping Failed",
	auditspi.EventNativeSSOExchange:        "Native SSO Exchange",
	auditspi.EventNativeSSOExchangeFailure: "Native SSO Exchange Failure",
	// admin control-plane (event_types_admin.go)
	auditspi.EventAdminClientCreated:              "Admin: Client Created",
	auditspi.EventAdminClientUpdated:              "Admin: Client Updated",
	auditspi.EventAdminClientDeleted:              "Admin: Client Deleted",
	auditspi.EventAdminClientSecretRotated:        "Admin: Client Secret Rotated",
	auditspi.EventAdminUserCreated:                "Admin: User Created",
	auditspi.EventAdminUserUpdated:                "Admin: User Updated",
	auditspi.EventAdminUserDeleted:                "Admin: User Deleted",
	auditspi.EventAdminTokenRevoked:               "Admin: Token Revoked",
	auditspi.EventAdminTempTokenIssued:            "Admin: Temp Token Issued",
	auditspi.EventAdminConsentRevoked:             "Admin: Consent Revoked",
	auditspi.EventAdminMFAFactorRemoved:           "Admin: MFA Factor Removed",
	auditspi.EventAdminRecoveryCodesReset:         "Admin: Recovery Codes Reset",
	auditspi.EventAdminPasswordReset:              "Admin: Password Reset",
	auditspi.EventAdminDeviceSecretsRevoked:       "Admin: Device Secrets Revoked",
	auditspi.EventAdminPasswordResetTokensRevoked: "Admin: Password Reset Tokens Revoked",
	auditspi.EventAdminEmailChangeTokensRevoked:   "Admin: Email Change Tokens Revoked",
	auditspi.EventAdminUserEmailChanged:           "Admin: User Email Changed",
	auditspi.EventAdminAccountUnlocked:            "Admin: Account Unlocked",
	auditspi.EventAdminConnectionUpserted:         "Admin: Connection Upserted",
	auditspi.EventAdminConnectionDeleted:          "Admin: Connection Deleted",
	auditspi.EventAdminTenantMemberAdded:          "Admin: Tenant Member Added",
	auditspi.EventAdminTenantMemberRemoved:        "Admin: Tenant Member Removed",
	auditspi.EventAdminRoleAdded:                  "Admin: Role Added",
	auditspi.EventAdminRoleUpdated:                "Admin: Role Updated",
	auditspi.EventAdminRoleRemoved:                "Admin: Role Removed",
	auditspi.EventAdminRoleAssigned:               "Admin: Role Assigned",
	auditspi.EventAdminRoleUnassigned:             "Admin: Role Unassigned",
	auditspi.EventAdminMenusUpdated:               "Admin: Menus Updated",
	auditspi.EventAdminTenantCreated:              "Admin: Tenant Created",
	auditspi.EventAdminTenantUpdated:              "Admin: Tenant Updated",
	auditspi.EventAdminTenantDeleted:              "Admin: Tenant Deleted",
	auditspi.EventAdminTenantStatusChanged:        "Admin: Tenant Status Changed",
	auditspi.EventAdminDomainCreated:              "Admin: Domain Created",
	auditspi.EventAdminDomainUpdated:              "Admin: Domain Updated",
	auditspi.EventAdminDomainDeleted:              "Admin: Domain Deleted",
	auditspi.EventAdminSubjectExported:            "Admin: Subject Exported",
	auditspi.EventAdminSubjectErased:              "Admin: Subject Erased",
	auditspi.EventAdminGRPCCalled:                 "Admin: gRPC Call",
	// system / platform (event_types_system.go)
	auditspi.EventBootstrapStepApplied:           "Bootstrap Step Applied",
	auditspi.EventBootstrapStepSkipped:           "Bootstrap Step Skipped",
	auditspi.EventBootstrapStepFailed:            "Bootstrap Step Failed",
	auditspi.EventBootstrapLockAcquired:          "Bootstrap Lock Acquired",
	auditspi.EventBootstrapLockReleased:          "Bootstrap Lock Released",
	auditspi.EventBootstrapLockLost:              "Bootstrap Lock Lost",
	auditspi.EventBootstrapLockContended:         "Bootstrap Lock Contended",
	auditspi.EventSnapshotExported:               "Snapshot Exported",
	auditspi.EventSnapshotRestored:               "Snapshot Restored",
	auditspi.EventSnapshotDeleted:                "Snapshot Deleted",
	auditspi.EventReleaseRegistered:              "Release Registered",
	auditspi.EventReleasePinned:                  "Release Pinned",
	auditspi.EventReleaseRolledBack:              "Release Rolled Back",
	auditspi.EventReleaseDeleted:                 "Release Deleted",
	auditspi.EventSigningKeyRotated:              "Signing Key Rotated",
	auditspi.EventSigningKeyAggregationDegraded:  "Signing Key Aggregation Degraded",
	auditspi.EventSigningKeyAggregationRecovered: "Signing Key Aggregation Recovered",
	auditspi.EventSigningKeyRotationCoordinated:  "Signing Key Rotation Coordinated",
	auditspi.EventSigningKeyAdoptionErrorsTotal:  "Signing Key Adoption Errors",
	auditspi.EventCAEPSetSent:                    "CAEP SET Sent",
	auditspi.EventSSFSetReceived:                 "SSF SET Received",
	auditspi.EventInvalidationBusDegraded:        "Invalidation Bus Degraded",
	auditspi.EventInvalidationBusReconnected:     "Invalidation Bus Reconnected",
}

const (
	cefGenericClassID   = "generic"
	cefGenericEventName = "SSO Event"
)

// cefClassID returns the CEF Device Event Class ID for t. The event type's
// own wire string doubles as its class ID — CEF class IDs are free-form
// per-vendor strings, so reusing the wire value means a brand-new EventType
// const (added by a later feature) gets a stable, unique class ID with zero
// risk of an accidentally-empty header field.
func cefClassID(t auditspi.EventType) string {
	if t == "" {
		return cefGenericClassID
	}
	return string(t)
}

// cefName renders the CEF "Name" field: the curated cefEventNames entry, or
// an automatically humanized fallback (snake_case -> Title Case words) for
// any type absent from the table.
func cefName(t auditspi.EventType) string {
	if name, ok := cefEventNames[t]; ok {
		return name
	}
	return humanizeEventType(t)
}

// humanizeEventType turns "admin_client_created" into "Admin Client
// Created". Used only as cefName's fallback for types the curated table
// doesn't (yet) cover — never empty for a non-empty t.
func humanizeEventType(t auditspi.EventType) string {
	if t == "" {
		return cefGenericEventName
	}
	words := strings.Split(string(t), "_")
	for i, w := range words {
		if w == "" {
			continue
		}
		r := []rune(w)
		r[0] = unicode.ToUpper(r[0])
		words[i] = string(r)
	}
	return strings.Join(words, " ")
}

// cefHeaderEscape escapes CEF header fields (Vendor/Product/Version/Class
// ID/Name): per spec, '\' and '|' must be backslash-escaped since '|' is the
// header field delimiter.
func cefHeaderEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`).Replace(s)
}

// cefExtensionEscape escapes a CEF extension value: '\', '=' (the key/value
// delimiter), and embedded newlines must be backslash-escaped.
func cefExtensionEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// cefKV appends an escaped "key=value" pair when value is non-empty —
// CEF omits absent optional fields rather than emitting them blank.
func cefKV(parts []string, key, value string) []string {
	if value == "" {
		return parts
	}
	return append(parts, key+"="+cefExtensionEscape(value))
}

// cefCustomString appends the "csNLabel=label csN=value" pair (CEF's
// generic custom-string extension mechanism) when value is non-empty. N
// must be 1-6, the six slots CEF reserves for vendor-defined strings.
func cefCustomString(parts []string, n int, label, value string) []string {
	if value == "" {
		return parts
	}
	idx := strconv.Itoa(n)
	return append(parts, "cs"+idx+"Label="+label, "cs"+idx+"="+cefExtensionEscape(value))
}

// cefStandardExtension builds the fixed-position CEF extension key=value
// pairs from e's well-known fields: CEF-reserved keys (rt/externalId/
// outcome/src/suser/requestClientApplication/msg) where CEF defines one,
// the cs1-cs6 custom-string slots otherwise.
func cefStandardExtension(e *auditspi.Event) []string {
	parts := []string{
		"rt=" + strconv.FormatInt(e.Timestamp.UnixMilli(), 10),
		"externalId=" + cefExtensionEscape(e.ID),
		"outcome=" + string(e.Outcome),
	}
	parts = cefKV(parts, "src", e.ActorIP)
	parts = cefKV(parts, "suser", e.ActorID)
	parts = cefKV(parts, "requestClientApplication", e.UserAgent)
	parts = cefKV(parts, "msg", e.Reason)
	parts = cefCustomString(parts, 1, "TenantID", e.TenantID)
	parts = cefCustomString(parts, 2, "ClientID", e.ClientID)
	parts = cefCustomString(parts, 3, "SessionID", e.SessionID)
	parts = cefCustomString(parts, 4, "RequestID", e.RequestID)
	parts = cefCustomString(parts, 5, "TraceID", e.TraceID)
	parts = cefCustomString(parts, 6, "TokenID", e.TokenID)
	return parts
}

// cefMetadataExtension appends one "meta.<key>=<value>" pair per Metadata
// entry, sorted by key — map iteration order is otherwise randomized, which
// would make golden-output tests (and real SIEM diffing) flaky.
func cefMetadataExtension(parts []string, meta map[string]string) []string {
	if len(meta) == 0 {
		return parts
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		parts = append(parts, "meta."+cefExtensionEscape(k)+"="+cefExtensionEscape(meta[k]))
	}
	return parts
}

// FormatCEF returns a Formatter emitting ArcSight CEF version 0 lines: one
// per Event (WriterSink appends the trailing '\n'). vendor/product/version
// fill the CEF header's Device Vendor/Product/Version fields — config-
// supplied by the caller, with Snaplink/SSO/<build version> as the
// operator-facing defaults (see
// cmd/sso-server/serverbuildauthn.BuildAuditSIEMSinks). The returned
// closure is a pure, transport-independent []byte encoder — roadmap item
// 19 (Kafka/NATS) reuses it unchanged over a different transport.
func FormatCEF(vendor, product, version string) Formatter {
	return func(e *auditspi.Event) ([]byte, error) {
		sev := toCEFSeverity(eventSeverity(e))
		header := strings.Join([]string{
			"CEF:0",
			cefHeaderEscape(vendor),
			cefHeaderEscape(product),
			cefHeaderEscape(version),
			cefHeaderEscape(cefClassID(e.Type)),
			cefHeaderEscape(cefName(e.Type)),
			strconv.Itoa(sev),
		}, "|")
		parts := cefMetadataExtension(cefStandardExtension(e), e.Metadata)
		return []byte(header + "|" + strings.Join(parts, " ")), nil
	}
}

// NewCEFSink is a thin WriterSink constructor pairing FormatCEF with a
// concrete output target.
func NewCEFSink(w io.Writer, vendor, product, version string) *WriterSink {
	return NewWriterSink(w, WithWriterFormat(FormatCEF(vendor, product, version)))
}
