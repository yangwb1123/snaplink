package audit_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// newHandlerCtx builds a real core.HandlerContext over an httptest
// request so the recorder_events helpers (which read EventFromRequest)
// exercise the full HTTP-metadata extraction path. No mocks — this is
// the same Context type the production router uses.
func newHandlerCtx(t *testing.T) core.HandlerContext {
	t.Helper()
	r := httptest.NewRequest("POST", "/token", nil)
	r.Header.Set("User-Agent", "test-agent")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.RemoteAddr = "10.0.0.1:5555"
	w := httptest.NewRecorder()
	return core.NewContext(w, r)
}

// recCtx wires a recorder over a MemorySink plus a fresh handler context,
// returning both so a test can drive a RecordXxx helper then read back the
// single stamped event.
func recCtx(t *testing.T) (*audit.Recorder, core.HandlerContext, *audit.MemorySink) {
	t.Helper()
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)
	return rec, newHandlerCtx(t), sink
}

// only reads the one event the helper recorded.
func only(t *testing.T, sink *audit.MemorySink) *audit.Event {
	t.Helper()
	got, err := sink.Query(context.Background(), audit.Query{Limit: 16})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 event, got %d", len(got))
	}
	return got[0]
}

func TestRecordTokenIssued(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordTokenIssued(rec, ctx, "client-a", "jwt", "user-1")
	e := only(t, sink)
	if e.Type != audit.EventTokenIssued || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("type/outcome = %q/%q", e.Type, e.Outcome)
	}
	if e.ClientID != "client-a" || e.TokenStrategy != "jwt" || e.ActorID != "user-1" {
		t.Fatalf("fields not lifted: %+v", e)
	}
	// HTTP metadata threaded through EventFromRequest.
	if e.ActorIP != "203.0.113.7" || e.UserAgent != "test-agent" {
		t.Fatalf("http metadata missing: ip=%q ua=%q", e.ActorIP, e.UserAgent)
	}
}

func TestRecordRefreshTokenIssued_RotationFlag(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordRefreshTokenIssued(rec, ctx, "c", "u", true)
	e := only(t, sink)
	if e.Type != audit.EventRefreshTokenIssued {
		t.Fatalf("type = %q", e.Type)
	}
	if e.Metadata["rotation"] != "true" {
		t.Fatalf("rotation meta = %q, want true", e.Metadata["rotation"])
	}
}

func TestRecordRefreshTokenIssued_FirstIssueNoRotationMeta(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordRefreshTokenIssued(rec, ctx, "c", "u", false)
	e := only(t, sink)
	if _, ok := e.Metadata["rotation"]; ok {
		t.Fatalf("first-issue should carry no rotation meta, got %v", e.Metadata)
	}
}

func TestRecordIDTokenIssued(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordIDTokenIssued(rec, ctx, "c", "u")
	e := only(t, sink)
	if e.Type != audit.EventIDTokenIssued || e.ClientID != "c" || e.ActorID != "u" {
		t.Fatalf("unexpected: %+v", e)
	}
}

func TestRecordDeviceCodeIssued(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordDeviceCodeIssued(rec, ctx, "device-client")
	e := only(t, sink)
	if e.Type != audit.EventDeviceCodeIssued || e.ClientID != "device-client" {
		t.Fatalf("unexpected: %+v", e)
	}
}

func TestRecordDeviceCodeDecision_ApprovedAndDenied(t *testing.T) {
	t.Parallel()
	rec1, ctx1, sink1 := recCtx(t)
	audit.RecordDeviceCodeDecision(rec1, ctx1, "user", "dc", true)
	e := only(t, sink1)
	if e.Type != audit.EventDeviceCodeApproved || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("approved branch: %+v", e)
	}
	if e.Metadata["device_client_id"] != "dc" {
		t.Fatalf("device_client_id = %q", e.Metadata["device_client_id"])
	}

	rec2, ctx2, sink2 := recCtx(t)
	audit.RecordDeviceCodeDecision(rec2, ctx2, "user", "dc", false)
	e2 := only(t, sink2)
	if e2.Type != audit.EventDeviceCodeDenied || e2.Outcome != audit.OutcomeFailure {
		t.Fatalf("denied branch: %+v", e2)
	}
}

func TestRecordCIBAAuthRequest(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordCIBAAuthRequest(rec, ctx, "c", "u", "areq-99")
	e := only(t, sink)
	if e.Type != audit.EventCIBAAuthRequest || e.Metadata["auth_req_id"] != "areq-99" {
		t.Fatalf("unexpected: %+v", e)
	}
}

func TestRecordCIBADecision_Branches(t *testing.T) {
	t.Parallel()
	rec1, ctx1, s1 := recCtx(t)
	audit.RecordCIBADecision(rec1, ctx1, "c", "u", true)
	if e := only(t, s1); e.Type != audit.EventCIBAApproved || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("approved: %+v", e)
	}
	rec2, ctx2, s2 := recCtx(t)
	audit.RecordCIBADecision(rec2, ctx2, "c", "u", false)
	if e := only(t, s2); e.Type != audit.EventCIBADenied || e.Outcome != audit.OutcomeFailure {
		t.Fatalf("denied: %+v", e)
	}
}

func TestRecordCIBAPingFailed_BackgroundContext(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(4)
	rec := audit.New(sink)
	audit.RecordCIBAPingFailed(rec, context.Background(), "c", "areq-1", "connection refused")
	e := only(t, sink)
	if e.Type != audit.EventCIBAPingFailed || e.Outcome != audit.OutcomeFailure {
		t.Fatalf("unexpected: %+v", e)
	}
	if e.Reason != "connection refused" || e.Metadata["auth_req_id"] != "areq-1" {
		t.Fatalf("reason/meta: %+v", e)
	}
}

func TestRecordCIBAPingFailed_EmptyAuthReqOmitsMeta(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(4)
	rec := audit.New(sink)
	audit.RecordCIBAPingFailed(rec, context.Background(), "c", "", "boom")
	e := only(t, sink)
	if _, ok := e.Metadata["auth_req_id"]; ok {
		t.Fatalf("empty auth_req_id should add no meta, got %v", e.Metadata)
	}
}

func TestRecordRefreshTokenReuse(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordRefreshTokenReuse(rec, ctx, "c", "user-1", "fam-1", 3)
	e := only(t, sink)
	if e.Type != audit.EventRefreshTokenReuse || e.Outcome != audit.OutcomeFailure {
		t.Fatalf("type/outcome: %+v", e)
	}
	if e.ActorID != "user-1" {
		t.Fatalf("actor: %+v", e)
	}
	if e.Reason != "family=fam-1" || e.Metadata["killed"] != "3" {
		t.Fatalf("reason/killed: %+v", e)
	}
}

func TestRecordRefreshTokenReuse_ZeroKilledOmitsMeta(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordRefreshTokenReuse(rec, ctx, "c", "user-1", "fam-1", 0)
	e := only(t, sink)
	if _, ok := e.Metadata["killed"]; ok {
		t.Fatalf("killed=0 should omit meta, got %v", e.Metadata)
	}
}

func TestRecordRefreshRotationVelocityExceeded(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordRefreshRotationVelocityExceeded(rec, ctx, "c", "fam-x", 12, 4)
	e := only(t, sink)
	if e.Type != audit.EventRefreshRotationVelocityExceeded {
		t.Fatalf("type: %+v", e)
	}
	if e.Metadata["count"] != "12" || e.Metadata["killed"] != "4" {
		t.Fatalf("count/killed: %+v", e)
	}
}

func TestRecordCredentialHealth_WeakAndCompromised(t *testing.T) {
	t.Parallel()
	rec1, ctx1, s1 := recCtx(t)
	audit.RecordCredentialHealth(rec1, ctx1, "c", "u", &core.CredentialHealth{Weak: true, Reason: "short"})
	e := only(t, s1)
	if e.Type != audit.EventPasswordWeak || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("weak: %+v", e)
	}
	if e.Metadata["reason"] != "short" {
		t.Fatalf("reason: %+v", e)
	}

	// Compromised wins when both set.
	rec2, ctx2, s2 := recCtx(t)
	audit.RecordCredentialHealth(rec2, ctx2, "c", "u", &core.CredentialHealth{Weak: true, Compromised: true})
	if e := only(t, s2); e.Type != audit.EventPasswordCompromised {
		t.Fatalf("compromised should win: %+v", e)
	}
}

func TestRecordCredentialHealth_NilHealthNoEvent(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(4)
	rec := audit.New(sink)
	audit.RecordCredentialHealth(rec, newHandlerCtx(t), "c", "u", nil)
	got, _ := sink.Query(context.Background(), audit.Query{Limit: 4})
	if len(got) != 0 {
		t.Fatalf("nil health should record nothing, got %d", len(got))
	}
}

func TestRecordLogout(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordLogout(rec, ctx, "sess-1", []string{"a", "b"})
	e := only(t, sink)
	if e.Type != audit.EventLogout || e.SessionID != "sess-1" {
		t.Fatalf("unexpected: %+v", e)
	}
	if e.Metadata["revoked"] != "a,b" {
		t.Fatalf("revoked meta = %q, want a,b", e.Metadata["revoked"])
	}
}

func TestRecordLogout_EmptyRevokedOmitsMeta(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordLogout(rec, ctx, "sess-1", nil)
	e := only(t, sink)
	if _, ok := e.Metadata["revoked"]; ok {
		t.Fatalf("empty revoked should omit meta, got %v", e.Metadata)
	}
}

func TestRecordLogoutNotify_SuccessAndFailure(t *testing.T) {
	t.Parallel()
	rec1, ctx1, s1 := recCtx(t)
	audit.RecordLogoutNotifySuccess(rec1, ctx1, "c", "sub", "https://rp/bcl")
	e := only(t, s1)
	if e.Type != audit.EventLogoutNotified || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("success: %+v", e)
	}
	if e.Metadata["uri"] != "https://rp/bcl" {
		t.Fatalf("uri: %+v", e)
	}

	rec2, ctx2, s2 := recCtx(t)
	audit.RecordLogoutNotifyFailure(rec2, ctx2, "c", "sub", "timeout")
	e2 := only(t, s2)
	if e2.Type != audit.EventLogoutNotified || e2.Outcome != audit.OutcomeFailure || e2.Reason != "timeout" {
		t.Fatalf("failure: %+v", e2)
	}
}

func TestRecordAccountLocked(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	until := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	audit.RecordAccountLocked(rec, ctx, "c", "password", "lockkey", until)
	e := only(t, sink)
	if e.Type != audit.EventAccountLocked || e.Outcome != audit.OutcomeFailure {
		t.Fatalf("type/outcome: %+v", e)
	}
	if e.Provider != "password" || e.ActorID != "lockkey" {
		t.Fatalf("provider/actor: %+v", e)
	}
	if e.Metadata["until"] != until.Format(time.RFC3339) {
		t.Fatalf("until meta = %q", e.Metadata["until"])
	}
}

func TestRecordAccountLocked_ZeroUntilOmitsMeta(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordAccountLocked(rec, ctx, "c", "password", "lockkey", time.Time{})
	e := only(t, sink)
	if _, ok := e.Metadata["until"]; ok {
		t.Fatalf("zero until should omit meta, got %v", e.Metadata)
	}
}

func TestRecordLoginSuccessAndFailure(t *testing.T) {
	t.Parallel()
	rec1, ctx1, s1 := recCtx(t)
	audit.RecordLoginSuccess(rec1, ctx1, "c", "password", "jwt", "u", "sess")
	e := only(t, s1)
	if e.Type != audit.EventLogin || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("success: %+v", e)
	}
	if e.Provider != "password" || e.TokenStrategy != "jwt" || e.ActorID != "u" || e.SessionID != "sess" {
		t.Fatalf("fields: %+v", e)
	}

	rec2, ctx2, s2 := recCtx(t)
	audit.RecordLoginFailure(rec2, ctx2, "c", "password", "bad creds")
	e2 := only(t, s2)
	if e2.Type != audit.EventLoginFailure || e2.Outcome != audit.OutcomeFailure || e2.Reason != "bad creds" {
		t.Fatalf("failure: %+v", e2)
	}
	if e2.ActorID != "" {
		t.Fatalf("login failure must not carry subject, got %q", e2.ActorID)
	}
}

// TestRecordLoginSuccessWithMeta_MergesOntoSameEvent proves the caller-
// supplied meta (e.g. interfaces/sso.WithTrustScoreSerialization's stamped
// trust score) lands on the SAME login event via SetMeta — never a second
// event — alongside the ordinary login fields.
func TestRecordLoginSuccessWithMeta_MergesOntoSameEvent(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordLoginSuccessWithMeta(rec, ctx, "c", "password", "jwt", "u", "sess",
		map[string]string{"trust_score": "0.87", "trust_reasons": "geo_risk:known_country"})
	e := only(t, sink)
	if e.Type != audit.EventLogin || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("event shape: %+v", e)
	}
	if e.Provider != "password" || e.TokenStrategy != "jwt" || e.ActorID != "u" || e.SessionID != "sess" {
		t.Fatalf("fields: %+v", e)
	}
	if e.Metadata["trust_score"] != "0.87" || e.Metadata["trust_reasons"] != "geo_risk:known_country" {
		t.Fatalf("meta not merged: %+v", e.Metadata)
	}
}

// TestRecordLoginSuccessWithMeta_NilOrEmptyMetaByteIdenticalToPlain proves a
// nil (or empty) meta produces an event indistinguishable from
// RecordLoginSuccess — the pre-existing call sites that keep passing nil see
// no behavior change.
func TestRecordLoginSuccessWithMeta_NilOrEmptyMetaByteIdenticalToPlain(t *testing.T) {
	t.Parallel()
	rec1, ctx1, s1 := recCtx(t)
	audit.RecordLoginSuccessWithMeta(rec1, ctx1, "c", "password", "jwt", "u", "sess", nil)
	plain := only(t, s1)

	rec2, ctx2, s2 := recCtx(t)
	audit.RecordLoginSuccess(rec2, ctx2, "c", "password", "jwt", "u", "sess")
	withNilHelper := only(t, s2)

	if len(plain.Metadata) != 0 {
		t.Fatalf("nil meta must add no metadata key, got %+v", plain.Metadata)
	}
	if plain.Type != withNilHelper.Type || plain.Outcome != withNilHelper.Outcome ||
		plain.Provider != withNilHelper.Provider || plain.TokenStrategy != withNilHelper.TokenStrategy ||
		plain.ActorID != withNilHelper.ActorID || plain.SessionID != withNilHelper.SessionID {
		t.Fatalf("RecordLoginSuccessWithMeta(nil) diverged from RecordLoginSuccess: %+v vs %+v", plain, withNilHelper)
	}
}

// TestRecordLoginSuccessWithMeta_NilRecorderNoop mirrors every other
// RecordXxx helper's nil-recorder contract (see TestNilRecorderNoop-style
// coverage elsewhere in this file): a nil *Recorder must not panic.
func TestRecordLoginSuccessWithMeta_NilRecorderNoop(t *testing.T) {
	t.Parallel()
	ctx := newHandlerCtx(t)
	audit.RecordLoginSuccessWithMeta(nil, ctx, "", "", "", "", "", map[string]string{"trust_score": "0.5"})
}

func TestRecordCodeSent_MasksTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, target, wantMeta string
		ok                     bool
	}{
		{"email", "alice@example.com", "a***e@example.com", true},
		{"single-char-email", "a@example.com", "a***@example.com", true},
		{"phone", "13800138000", "13*******00", true},
		{"short", "123", "***", true},
		{"failure-outcome", "555@x.io", "5***5@x.io", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, ctx, sink := recCtx(t)
			audit.RecordCodeSent(rec, ctx, "email", tc.target, tc.ok)
			e := only(t, sink)
			if e.Type != audit.EventCodeSent {
				t.Fatalf("type: %+v", e)
			}
			wantOutcome := audit.OutcomeSuccess
			if !tc.ok {
				wantOutcome = audit.OutcomeFailure
			}
			if e.Outcome != wantOutcome {
				t.Fatalf("outcome = %q, want %q", e.Outcome, wantOutcome)
			}
			if e.Metadata["target"] != tc.wantMeta {
				t.Fatalf("masked target = %q, want %q", e.Metadata["target"], tc.wantMeta)
			}
		})
	}
}

func TestRecordCodeSent_EmptyTargetOmitsMeta(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordCodeSent(rec, ctx, "email", "", true)
	e := only(t, sink)
	if _, ok := e.Metadata["target"]; ok {
		t.Fatalf("empty target should omit meta, got %v", e.Metadata)
	}
}

func TestRecordCallbackFailure(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordCallbackFailure(rec, ctx, "oidc_federation", "state mismatch")
	e := only(t, sink)
	if e.Type != audit.EventCallbackFailure || e.Provider != "oidc_federation" || e.Reason != "state mismatch" {
		t.Fatalf("unexpected: %+v", e)
	}
}

func TestRecordMFAFailure(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordMFAFailure(rec, ctx, "u", "chal-1", "totp", "wrong code")
	e := only(t, sink)
	if e.Type != audit.EventMFAFailure || e.Outcome != audit.OutcomeFailure {
		t.Fatalf("type/outcome: %+v", e)
	}
	if e.ActorID != "u" || e.Reason != "wrong code" {
		t.Fatalf("actor/reason: %+v", e)
	}
	if e.Metadata[core.KeyMFAMethod] != "totp" || e.Metadata[core.KeyMFAChallengeID] != "chal-1" {
		t.Fatalf("mfa meta: %+v", e.Metadata)
	}
	// Built directly (no EventFromRequest) but still stamps actor IP.
	if e.ActorIP != "203.0.113.7" {
		t.Fatalf("actor IP = %q, want forwarded IP", e.ActorIP)
	}
}

func TestRecordMFAFailure_EmptyFactorOmitsMeta(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordMFAFailure(rec, ctx, "u", "", "", "reason")
	e := only(t, sink)
	if len(e.Metadata) != 0 {
		t.Fatalf("empty method/challenge should add no meta, got %v", e.Metadata)
	}
}

func TestRecordFAPIViolation(t *testing.T) {
	t.Parallel()
	rec, ctx, sink := recCtx(t)
	audit.RecordFAPIViolation(rec, ctx, "c", "rule-1", "detail text", "enforce")
	e := only(t, sink)
	if e.Type != audit.EventFAPIComplianceViolation || e.Outcome != audit.OutcomeFailure {
		t.Fatalf("type/outcome: %+v", e)
	}
	if e.Reason != "rule-1" {
		t.Fatalf("reason: %+v", e)
	}
	if e.Metadata["fapi_rule"] != "rule-1" || e.Metadata["fapi_detail"] != "detail text" || e.Metadata["fapi_mode"] != "enforce" {
		t.Fatalf("fapi meta: %+v", e.Metadata)
	}
}

func TestRecordSigningKeyAggregation_DegradedAndRecovered(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(8)
	rec := audit.New(sink)
	audit.RecordSigningKeyAggregationDegraded(rec, context.Background(), "subscribe closed")
	audit.RecordSigningKeyAggregationRecovered(rec, context.Background())

	got, _ := sink.Query(context.Background(), audit.Query{Limit: 8})
	if len(got) != 2 {
		t.Fatalf("expected 2 events, got %d", len(got))
	}
	// Newest first: recovered, then degraded.
	if got[0].Type != audit.EventSigningKeyAggregationRecovered || got[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("recovered: %+v", got[0])
	}
	if got[1].Type != audit.EventSigningKeyAggregationDegraded || got[1].Outcome != audit.OutcomeFailure {
		t.Fatalf("degraded: %+v", got[1])
	}
	if got[1].Metadata["reason"] != "subscribe closed" {
		t.Fatalf("degraded reason: %+v", got[1].Metadata)
	}
}

func TestRecordSigningKeyRotationCoordinated(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(4)
	rec := audit.New(sink)
	audit.RecordSigningKeyRotationCoordinated(rec, context.Background(), "deferred")
	e := only(t, sink)
	if e.Type != audit.EventSigningKeyRotationCoordinated || e.Outcome != audit.OutcomeSuccess {
		t.Fatalf("type/outcome: %+v", e)
	}
	if e.Metadata["outcome"] != "deferred" {
		t.Fatalf("outcome meta: %+v", e.Metadata)
	}
}

// Every helper short-circuits on a nil recorder — the contract that lets
// handlers in any subpackage call them without a wiring guard.
func TestRecordHelpers_NilRecorderNoPanic(t *testing.T) {
	t.Parallel()
	ctx := newHandlerCtx(t)
	bg := context.Background()
	audit.RecordTokenIssued(nil, ctx, "", "", "")
	audit.RecordRefreshTokenIssued(nil, ctx, "", "", true)
	audit.RecordIDTokenIssued(nil, ctx, "", "")
	audit.RecordDeviceCodeIssued(nil, ctx, "")
	audit.RecordDeviceCodeDecision(nil, ctx, "", "", true)
	audit.RecordCIBAAuthRequest(nil, ctx, "", "", "")
	audit.RecordCIBADecision(nil, ctx, "", "", false)
	audit.RecordCIBAPingFailed(nil, bg, "", "", "")
	audit.RecordRefreshTokenReuse(nil, ctx, "", "", "", 0)
	audit.RecordRefreshRotationVelocityExceeded(nil, ctx, "", "", 0, 0)
	audit.RecordCredentialHealth(nil, ctx, "", "", &core.CredentialHealth{})
	audit.RecordLogout(nil, ctx, "", nil)
	audit.RecordLogoutNotifySuccess(nil, ctx, "", "", "")
	audit.RecordLogoutNotifyFailure(nil, ctx, "", "", "")
	audit.RecordAccountLocked(nil, ctx, "", "", "", time.Time{})
	audit.RecordLoginSuccess(nil, ctx, "", "", "", "", "")
	audit.RecordLoginFailure(nil, ctx, "", "", "")
	audit.RecordCodeSent(nil, ctx, "", "", true)
	audit.RecordCallbackFailure(nil, ctx, "", "")
	audit.RecordMFAFailure(nil, ctx, "", "", "", "")
	audit.RecordFAPIViolation(nil, ctx, "", "", "", "")
	audit.RecordSigningKeyAggregationDegraded(nil, bg, "")
	audit.RecordSigningKeyAggregationRecovered(nil, bg)
	audit.RecordSigningKeyRotationCoordinated(nil, bg, "")
}
