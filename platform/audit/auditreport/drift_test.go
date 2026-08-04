package auditreport_test

import (
	"sort"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditreport"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// wantUncategorizedEventTypes is every audit.EventType constant that, at
// authoring time, controlAreaDefs deliberately does NOT claim into a
// named control area — DCR/network/CIBA/bootstrap/release/CAEP/token-
// lifecycle plumbing with no direct SOC2 evidentiary role in this pass.
// Referencing the real constants (not string literals) means a rename or
// removal fails this file at compile time.
//
// This is the "the test names the gap" half of the brief's drift
// design: TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized
// below asserts this list, PLUS controlAreaDefs' union, together cover
// every entry in auditspi.KnownEventTypes exactly once. A NEW EventType
// constant added later to KnownEventTypes without a corresponding
// addition HERE (or to a controlAreaDefs bucket) makes that test fail
// loudly, naming exactly which constant drifted — never silently
// vanishing into a shipped compliance artifact's Uncategorized bucket
// unnoticed.
var wantUncategorizedEventTypes = []audit.EventType{
	audit.EventTokenIssued, audit.EventTokenRevoked, audit.EventCodeSent, audit.EventCallbackFailure,
	audit.EventClientRegistered, audit.EventClientUpdated, audit.EventClientDeleted,
	audit.EventNetPolicyApply, audit.EventNetPolicyDelete, audit.EventLogoutNotified,
	audit.EventPartialRevokeFailure, audit.EventTenantTokensRevoked, audit.EventTenantSessionsRevoked,
	audit.EventPasswordResetRequested, audit.EventPasswordResetCompleted, audit.EventPasswordResetFailed,
	audit.EventConsentGranted, audit.EventConsentRevoked, audit.EventConsentDenied,
	audit.EventSelfRegistered, audit.EventEmailChangeRequested, audit.EventEmailChanged,
	audit.EventOrgLeft, audit.EventOrgMemberAutoProvisioned, audit.EventInvitationSent,
	audit.EventInvitationAccepted, audit.EventInvitationRevoked,
	audit.EventPasswordWeak, audit.EventPasswordCompromised, audit.EventSPIFFEJWTSVIDAccepted,
	audit.EventRefreshTokenIssued, audit.EventIDTokenIssued, audit.EventDeviceCodeIssued,
	audit.EventDeviceCodeApproved, audit.EventDeviceCodeDenied,
	audit.EventCIBAAuthRequest, audit.EventCIBAApproved, audit.EventCIBADenied, audit.EventCIBAPingFailed,
	audit.EventNativeSSOExchange, audit.EventNativeSSOExchangeFailure,
	audit.EventBootstrapStepApplied, audit.EventBootstrapStepSkipped, audit.EventBootstrapStepFailed,
	audit.EventBootstrapLockAcquired, audit.EventBootstrapLockReleased, audit.EventBootstrapLockLost,
	audit.EventBootstrapLockContended,
	audit.EventSnapshotExported, audit.EventSnapshotRestored, audit.EventSnapshotDeleted,
	audit.EventReleaseRegistered, audit.EventReleasePinned, audit.EventReleaseRolledBack, audit.EventReleaseDeleted,
	audit.EventCAEPSetSent, audit.EventSSFSetReceived,
	audit.EventInvalidationBusDegraded, audit.EventInvalidationBusReconnected,
	audit.EventDegradationModeChanged, audit.EventFeatureGatesDisabled,
	audit.EventConnectionAuthenticatorBuildFailed,
	// Fail-open degradation canary for the idempotency capture path.
	// Rate is unbounded by construction (one event per request that carried
	// an Idempotency-Key and reached commit without a capture wrapper — a
	// misconfig/regression detector, not a per-actor action), and the
	// metadata carries only a sha-256 prefix of the key. No SOC2 evidentiary
	// role for the pass; deliberately uncategorized so a future bucket
	// decision must be explicit.
	audit.EventIdempotencyCaptureMissing,
}

// namedAreaEventTypes returns the union of every controlAreaDefs entry's
// vocabulary, read through the exported ControlArea.EventTypes field
// (built over an EMPTY bundle so it reflects the static per-area
// vocabulary rather than anything observed) — a black-box read, no
// access to the unexported controlAreaDefs table itself.
func namedAreaEventTypes(t *testing.T) map[audit.EventType]string {
	t.Helper()
	empty := recordBundle(t, nil)
	report, err := auditreport.BuildSOC2Report(empty, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	claimed := map[audit.EventType]string{}
	for _, area := range report.ControlAreas {
		for _, et := range area.EventTypes {
			if prev, ok := claimed[et]; ok {
				t.Fatalf("event type %q claimed by both %q and %q — must appear in AT MOST one control area", et, prev, area.Code)
			}
			claimed[et] = area.Code
		}
	}
	return claimed
}

// TestControlAreaDefs_NoEventTypeClaimedTwice enforces controlAreaDefs'
// own internal consistency invariant (see control_areas.go's doc
// comment) — a duplicate listing would silently double-count a single
// event across two areas' TotalEvents.
func TestControlAreaDefs_NoEventTypeClaimedTwice(t *testing.T) {
	t.Parallel()
	_ = namedAreaEventTypes(t) // fails the test itself on any duplicate
}

// TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized is the
// EventType drift test the brief requires: every entry in
// auditspi.KnownEventTypes (the SDK's own catalogue of every event type
// it emits) must be EITHER claimed by a named controlAreaDefs bucket OR
// explicitly listed in wantUncategorizedEventTypes above. Anything in
// neither set is a genuine drift — a new EventType added to the SDK that
// nobody has yet decided where it belongs — and this test fails,
// printing exactly which constant(s) drifted.
func TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized(t *testing.T) {
	t.Parallel()
	claimed := namedAreaEventTypes(t)
	wantUncat := make(map[audit.EventType]bool, len(wantUncategorizedEventTypes))
	for _, et := range wantUncategorizedEventTypes {
		wantUncat[et] = true
	}

	var undecided []string
	for et := range auditspi.KnownEventTypes {
		if _, ok := claimed[et]; ok {
			continue
		}
		if wantUncat[et] {
			continue
		}
		undecided = append(undecided, string(et))
	}
	if len(undecided) > 0 {
		sort.Strings(undecided)
		t.Errorf("EventType(s) neither claimed by a control area nor listed in "+
			"wantUncategorizedEventTypes — file each one into control_areas.go or "+
			"drift_test.go's allowlist: %v", undecided)
	}

	// The converse: an allowlist entry that no longer exists in
	// KnownEventTypes is stale (renamed/removed elsewhere) — catches the
	// allowlist itself drifting out of date.
	var stale []string
	for et := range wantUncat {
		if _, ok := auditspi.KnownEventTypes[et]; !ok {
			stale = append(stale, string(et))
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("wantUncategorizedEventTypes has stale entries no longer in auditspi.KnownEventTypes: %v", stale)
	}
}

// TestBuildSOC2Report_HandlesEveryKnownEventType builds a real bundle
// carrying one event of EVERY type in auditspi.KnownEventTypes, proving
// BuildSOC2Report never panics or drops an event regardless of catalogue
// size, and that the sum invariant holds across the full real catalogue
// (not just the small fixtures used elsewhere in this package).
func TestBuildSOC2Report_HandlesEveryKnownEventType(t *testing.T) {
	t.Parallel()
	var recs []audit.Event
	for et := range auditspi.KnownEventTypes {
		recs = append(recs, audit.Event{Type: et, Outcome: audit.OutcomeSuccess, ActorID: "fixture"})
	}
	bundle := recordBundle(t, recs)
	if bundle.EventCount != len(auditspi.KnownEventTypes) {
		t.Fatalf("bundle.EventCount=%d, want %d", bundle.EventCount, len(auditspi.KnownEventTypes))
	}
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	sum := report.Uncategorized.TotalEvents
	for _, a := range report.ControlAreas {
		sum += a.TotalEvents
	}
	if sum != bundle.EventCount {
		t.Errorf("sum(areas)+Uncategorized=%d, want bundle.EventCount=%d", sum, bundle.EventCount)
	}
}
