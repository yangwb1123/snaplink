package compliance

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// DataCategory describes one category of personal data this server processes,
// for a GDPR Art. 30 "Records of Processing Activities" report: what it
// contains, which SPI/store persists it, and how it is retained. The catalog
// mirrors the ACTUAL shared/core (+ platform/audit) struct shapes by hand —
// update the relevant category function when one of those shapes changes —
// rather than reflecting them at runtime, since Art. 30 documents the
// SYSTEM's processing activities (a design-time fact), not a live query
// (Exporter already covers a data SUBJECT's live records).
type DataCategory struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Store           string   `json:"store"`
	Fields          []string `json:"fields"`
	LegalBasis      string   `json:"legal_basis"`
	RetentionPolicy string   `json:"retention_policy"`
}

// DataMap is the assembled Art. 30 processing-activity record.
type DataMap struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Categories  []DataCategory `json:"categories"`
}

// DataMapOptions folds the operator's ACTUAL configured retention windows
// into the generated categories, when known, so the report reflects live
// configuration rather than a generic placeholder. Every field is optional
// (zero ⇒ "not server-enforced / operator-managed elsewhere") so a caller
// that wires nothing still gets an accurate, generic description.
type DataMapOptions struct {
	// SessionTTL is the operator's configured session lifetime, if any
	// (informational — sessions also carry their own per-record ExpiresAt).
	SessionTTL time.Duration
	// ConsentMaxTTL mirrors WithConsentTTL — the server-enforced ceiling on
	// consent grant lifetime, if any.
	ConsentMaxTTL time.Duration
	// AuditRetentionMaxAge mirrors config.AuditConfig.Retention.MaxAge — how
	// long audit events are retained before they become prune-eligible.
	AuditRetentionMaxAge time.Duration
}

// BuildDataMap returns the current catalog of personal-data categories this
// server's default SPIs process. Static + opts-folded — see DataMapOptions.
func BuildDataMap(opts DataMapOptions) *DataMap {
	return &DataMap{
		GeneratedAt: time.Now().UTC(),
		Categories: []DataCategory{
			userProfileCategory(),
			sessionCategory(opts),
			consentCategory(opts),
			mfaEnrollmentCategory(),
			refreshTokenCategory(),
			auditLogCategory(opts),
		},
	}
}

func userProfileCategory() DataCategory {
	return DataCategory{
		Name:        "user_profile",
		Description: "Core account identity: external IdP link, contact info, display name, and operator-defined attributes.",
		Store:       "core.UserProvider (MemoryUserProvider, defaultimpl/sqlite users table, or an operator-supplied backend)",
		Fields:      []string{"id", "external_id", "provider", "email", "name", "attributes", "created_at", "updated_at"},
		LegalBasis:  "Contract (account provisioning) / legitimate interest (SSO service operation)",
		RetentionPolicy: "Until account deletion: admin-triggered erasure (protocols/compliance.Eraser) or the data " +
			"subject's own GDPR Art. 17 self-service request (POST /me/account/erase, when WithSelfServiceAccountErasure " +
			"is wired). No automatic time-based expiry — retention is decision-driven, not TTL-driven.",
	}
}

func sessionCategory(opts DataMapOptions) DataCategory {
	retention := "Each session carries its own ExpiresAt; expired sessions are refused on read and are eligible for " +
		"physical deletion by the opt-in data-retention sweep (protocols/compliance.RetentionSweeper, SessionTTLSweep)."
	if opts.SessionTTL > 0 {
		retention += " Operator-configured session lifetime: " + opts.SessionTTL.String() + "."
	}
	return DataCategory{
		Name:            "sessions",
		Description:     "Server-side login session records, including device/location context captured at creation.",
		Store:           "core.SessionManager (MemorySessionManager, defaultimpl/sqlite sessions table, or Redis)",
		Fields:          []string{"id", "user_id", "created_at", "expires_at", "revoked", "ip", "user_agent", "tenant_id"},
		LegalBasis:      "Contract (maintaining an authenticated session) / legitimate interest (security monitoring)",
		RetentionPolicy: retention,
	}
}

func consentCategory(opts DataMapOptions) DataCategory {
	retention := "Until revoked (RevokeConsent is a hard delete — no soft-delete/tombstone is kept) or ExpiresAt, when set."
	if opts.ConsentMaxTTL > 0 {
		retention += " Operator-enforced ceiling (WithConsentTTL): " + opts.ConsentMaxTTL.String() + "."
	} else {
		retention += " No server-enforced ceiling is currently configured — a grant lives until explicitly revoked."
	}
	return DataCategory{
		Name:            "consent_grants",
		Description:     "Per (user, client) OAuth scope-consent decisions.",
		Store:           "core.ConsentStore (MemoryConsentStore, defaultimpl/sqlite consent table, Redis, or Postgres)",
		Fields:          []string{"user_id", "client_id", "scopes", "granted_at", "expires_at"},
		LegalBasis:      "Consent (GDPR Art. 6(1)(a)) — the record IS the evidence of the data subject's authorization decision",
		RetentionPolicy: retention,
	}
}

func mfaEnrollmentCategory() DataCategory {
	return DataCategory{
		Name:        "mfa_enrollments",
		Description: "Registered second factors (TOTP, WebAuthn/passkey, push) bound to an account.",
		Store:       "core.MFAEnrollmentStore (backend-specific; e.g. defaultimpl/sqlite totp/webauthn tables)",
		Fields:      []string{"id", "method", "label", "added_at"},
		LegalBasis:  "Contract / legitimate interest (account security)",
		RetentionPolicy: "Until removed by the account holder (DELETE /me/mfa/:id), an admin (DELETE " +
			"/admin/users/:id/mfa/:id), or account erasure — no automatic time-based expiry.",
	}
}

func refreshTokenCategory() DataCategory {
	return DataCategory{
		Name:        "refresh_tokens",
		Description: "Long-lived OAuth refresh tokens (hashed at rest by every default backend), scoped per (user, client).",
		Store:       "oauth.RefreshTokenStore / RefreshTokenSubjectIndex (memory, defaultimpl/sqlite, Redis)",
		Fields:      []string{"user_id", "client_id", "provider", "scopes", "family_id", "issued_at", "expires_at"},
		LegalBasis:  "Contract (maintaining the OAuth grant without re-prompting the user)",
		RetentionPolicy: "Each token carries its own ExpiresAt; family reuse-detection deletes the whole family on " +
			"replay. Explicit revocation is per-subject-per-client (Eraser.EraseSubject enumerates every registered " +
			"client); there is no system-wide physical-expiry sweep in this SPI today (see RetentionSweeper doc).",
	}
}

func auditLogCategory(opts DataMapOptions) DataCategory {
	retention := "Operator-configured (config.AuditConfig.Retention.MaxAge, pruned by platform/audit/sqlite.Sink.Prune " +
		"when wired); the in-memory sink is capacity-bound (oldest-evicted ring buffer) rather than time-bound."
	if opts.AuditRetentionMaxAge > 0 {
		retention = "Configured retention window: " + opts.AuditRetentionMaxAge.String() + " (events older than this are prune-eligible)."
	}
	return DataCategory{
		Name:            "audit_log",
		Description:     "Security/compliance event trail: who did what, when, from where — includes actor identifiers and, in Metadata, the affected subject (e.g. target_user).",
		Store:           "platform/audit (audit.Sink: MemorySink or platform/audit/sqlite.Sink)",
		Fields:          []string{"id", "type", "outcome", "timestamp", "actor_id", "actor_ip", "user_agent", "session_id", "reason", "metadata"},
		LegalBasis:      "Legal obligation / legitimate interest (security monitoring, SOC2/GDPR Art. 30 accountability)",
		RetentionPolicy: retention,
	}
}

// HandleAdminDataMap serves GET /api/v1/admin/compliance/data-map — the
// GDPR Art. 30 processing-activity record. admin:read. No query parameters:
// the report describes the system's data model, not per-subject data, so
// there is nothing to filter by.
func HandleAdminDataMap(opts DataMapOptions, _ spi.Logger, ctx core.HandlerContext) {
	ctx.JSON(http.StatusOK, BuildDataMap(opts))
}
