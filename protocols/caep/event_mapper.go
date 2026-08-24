package caep

import (
	"encoding/json"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// scopeKind tells the broadcaster HOW to resolve the affected
// receiver(s) for a mapped audit event — the security crux of v1
// (decision 2: never broadcast one RP's revocation to every RP).
type scopeKind int

const (
	// scopeNone — the event does not map to any SSF event; do not broadcast.
	// Pinned as iota 0 so a zero-valued mappedEvent never broadcasts; do not
	// drop or the next scope becomes the zero value (wrong-receiver footgun).
	scopeNone scopeKind = iota //nolint:unused // zero-value sentinel: must stay iota 0

	// scopeClient — push to the single client named on the audit event
	// (Event.ClientID is the AFFECTED RP). Used when the event reliably
	// names the owning client of the revoked credential.
	scopeClient

	// scopeTenant — fan out to every client of the tenant named on the
	// event (Event.ActorID is the tenant id). A tenant-wide event (e.g. a
	// suspension that purged every client's tokens) notifies each of that
	// tenant's RPs — and ONLY that tenant's RPs.
	scopeTenant

	// scopeUser — fan out to the clients of the user's OWN tenant(s): the
	// event names an affected end-user (mappedEvent.userID), whose
	// memberships are resolved via the optional TenantUserStore and each
	// tenant's clients queried via TenantScopedClientStore — tenant events
	// query only that tenant. Used for user-lifecycle transitions, where
	// no single RP owns the affected credentials.
	scopeUser
)

// mappedEvent is the result of mapping one internal audit event onto the
// SSF wire: the `events` claim to embed plus how to scope delivery.
type mappedEvent struct {
	scope scopeKind

	// affectedClientID / tenantID / userID are resolved from the audit
	// event per scope. Exactly one is meaningful (the others are empty)
	// depending on scope. The broadcaster uses these to look up receivers
	// FRESH from the ClientStore — it never trusts a receiver address from
	// anywhere but registered client metadata.
	affectedClientID string
	tenantID         string
	userID           string

	// subject is the affected end-user (carried into the SET `sub_id`).
	subject string

	// events is the RFC 8417 `events` claim: one or more SSF/CAEP/RISC
	// URIs, each mapping to its (here, empty-object) per-event payload.
	events map[string]json.RawMessage
}

// emptyEventPayload is the conventional `{}` value for an SSF event whose
// URI alone carries the signal (RFC 8417 §1.2 permits any JSON object;
// the empty object is the minimal valid form, matching the BCL
// logout-token convention already used in this codebase).
var emptyEventPayload = json.RawMessage("{}")

// mapAuditEvent translates the SMALL set of existing internal audit
// events that correspond to a real-time cross-RP security signal into an
// SSF SET shape. It is deliberately conservative: an event it does not
// recognise returns (mappedEvent{}, false) so the broadcaster stays
// silent. Adding a new mapping is an explicit, reviewed change — the
// transmitter must never fan out an event it wasn't built to scope.
//
// Mappings (decision 2 scoping in parentheses):
//   - refresh_token_reuse_detected → session-revoked + token-claims-change
//     (scopeClient: Event.ClientID is the owning RP of the killed family).
//   - tenant_tokens_revoked → account-disabled + session-revoked
//     (scopeTenant: Event.ActorID is the tenant whose clients were purged).
//   - admin_token_revoked → token-revoked (scopeClient, but ONLY when the
//     affected RP is explicitly recorded via the caep_affected_client
//     metadata key — the admin-revoke audit event's own ClientID is the
//     ADMIN's client, not the token's owning RP, so pushing to it would be
//     a wrong-receiver leak. Absent that key the event does not broadcast;
//     the reliable multi-RP-per-subject fan-out is v2).
//   - admin_user_lifecycle_changed → account-disabled + session-revoked
//     (non-active target state) or account-enabled (target ACTIVE),
//     scopeUser: subject is the transition's target_user; receivers are
//     the clients of the user's OWN tenant(s) — tenant events query only
//     that tenant (decision: tenant dimension, see docs/design/lifecycle-caep-events.md).
func mapAuditEvent(e *audit.Event) (mappedEvent, bool) {
	if e == nil {
		return mappedEvent{}, false
	}
	switch e.Type {
	case audit.EventRefreshTokenReuse:
		return mapRefreshTokenReuse(e)
	case audit.EventTenantTokensRevoked:
		return mapTenantTokensRevoked(e)
	case audit.EventAdminTokenRevoked:
		return mapAdminTokenRevoked(e)
	case audit.EventAdminUserLifecycleChanged:
		return mapLifecycleChanged(e)
	default:
		return mappedEvent{}, false
	}
}

// mapRefreshTokenReuse maps a killed refresh-token family to a client-scoped
// session-revoked + token-claims-change signal. Event.ClientID is the owning
// RP; absent it (the per-case empty-field guard) we do not broadcast.
func mapRefreshTokenReuse(e *audit.Event) (mappedEvent, bool) {
	if e.ClientID == "" {
		return mappedEvent{}, false
	}
	return mappedEvent{
		scope:            scopeClient,
		affectedClientID: e.ClientID,
		subject:          e.ActorID,
		events: map[string]json.RawMessage{
			EventURICAEPSessionRevoked:    emptyEventPayload,
			EventURICAEPTokenClaimsChange: emptyEventPayload,
		},
	}, true
}

// mapTenantTokensRevoked maps a tenant-wide token purge to a tenant-scoped
// account-disabled + session-revoked signal. ActorID is the tenant id (see
// auditTenantTokensRevoked); absent it we do not broadcast.
func mapTenantTokensRevoked(e *audit.Event) (mappedEvent, bool) {
	if e.ActorID == "" {
		return mappedEvent{}, false
	}
	return mappedEvent{
		scope:    scopeTenant,
		tenantID: e.ActorID,
		subject:  e.ActorID,
		events: map[string]json.RawMessage{
			EventURIRISCAccountDisabled: emptyEventPayload,
			EventURICAEPSessionRevoked:  emptyEventPayload,
		},
	}, true
}

// mapAdminTokenRevoked maps an admin-initiated revoke to a client-scoped
// token-revoked signal. The affected RP must be named explicitly via metadata —
// the event's own ClientID is the calling admin's client. Without it, do NOT
// broadcast (no wrong-receiver push, no broadcast-to-all).
func mapAdminTokenRevoked(e *audit.Event) (mappedEvent, bool) {
	affected := metaValue(e, MetaAffectedClient)
	if affected == "" {
		return mappedEvent{}, false
	}
	return mappedEvent{
		scope:            scopeClient,
		affectedClientID: affected,
		subject:          metaValue(e, MetaSubject),
		events: map[string]json.RawMessage{
			EventURICAEPTokenRevoked: emptyEventPayload,
		},
	}, true
}

// mapLifecycleChanged maps a committed user-lifecycle transition to the
// SSF signal offline-validating RPs need: a non-active target state
// (INVITED/SUSPENDED/INACTIVE/ARCHIVED/PURGED) disables the account and
// revokes sessions; re-entering ACTIVE re-enables it. The subject is the
// transition's target user (the MetaTargetUser metadata every
// RecordTransition stamps — the event's own ActorID is the admin/system
// actor, never the affected end-user); the receivers are the clients of
// the user's own tenant(s), resolved fresh at delivery time (scopeUser).
// An event without a target user, or targeting an unrecognized state,
// does NOT broadcast — the same conservative silence as an unscoped
// admin_token_revoked.
func mapLifecycleChanged(e *audit.Event) (mappedEvent, bool) {
	userID := metaValue(e, userlifecycle.MetaTargetUser)
	to := userlifecycle.State(metaValue(e, userlifecycle.MetaToState))
	if userID == "" || !to.Valid() {
		return mappedEvent{}, false
	}
	var events map[string]json.RawMessage
	if userlifecycle.AllowsAuthentication(to) {
		events = map[string]json.RawMessage{
			EventURIRISCAccountEnabled: emptyEventPayload,
		}
	} else {
		events = map[string]json.RawMessage{
			EventURIRISCAccountDisabled: emptyEventPayload,
			EventURICAEPSessionRevoked:  emptyEventPayload,
		}
	}
	return mappedEvent{scope: scopeUser, userID: userID, subject: userID, events: events}, true
}

// metaValue reads a metadata key safely from a possibly-nil map.
func metaValue(e *audit.Event, key string) string {
	if e == nil || e.Metadata == nil {
		return ""
	}
	return e.Metadata[key]
}
