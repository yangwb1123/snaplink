package auditreport_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/audit/auditexport"
	"github.com/snaplink/sso/platform/audit/auditreport"
)

// chainBase anchors the synthetic clock so recorded events get strictly
// increasing, deterministic timestamps — mirrors auditexport_test.go's
// own fixture convention. A local copy (not a shared helper) per
// AGENTS.md's "tests beside code" norm: each leaf package's tests stay
// self-contained rather than depending on a sibling package's _test.go.
var chainBase = time.Unix(1700000000, 0).UTC()

// recordBundle drives recs through a hash-chained MemorySink, in order,
// and returns the resulting self-verified ExportBundle for
// BuildSOC2Report to consume. Real Recorder + real MemorySink — no
// mocks, per AGENTS.md ("Mocks where Memory* exists -> use real
// MemoryProvider/MemorySink").
func recordBundle(t *testing.T, recs []audit.Event) *auditexport.ExportBundle {
	t.Helper()
	sink := audit.NewMemorySink(len(recs) + 1)
	i := 0
	r := audit.New(sink, audit.WithHashChain(), audit.WithClock(func() time.Time {
		i++
		return chainBase.Add(time.Duration(i) * time.Hour)
	}))
	for _, e := range recs {
		ev := e
		r.Record(context.Background(), &ev)
	}
	b, err := auditexport.BuildExportBundle(context.Background(), sink, audit.Query{})
	if err != nil {
		t.Fatalf("BuildExportBundle: %v", err)
	}
	return b
}

func areasByCode(r *auditreport.SOC2Report) map[string]auditreport.ControlArea {
	m := make(map[string]auditreport.ControlArea, len(r.ControlAreas))
	for _, a := range r.ControlAreas {
		m[a.Code] = a
	}
	return m
}

func TestBuildSOC2Report_BucketsEventsByControlArea(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, []audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "bob"},
		{Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure, ActorID: "eve"},
		{Type: audit.EventMFASuccess, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
		{Type: audit.EventSigningKeyRotated, Outcome: audit.OutcomeSuccess, ActorID: "ops"},
		{Type: audit.EventAdminClientCreated, Outcome: audit.OutcomeSuccess, ActorID: "admin1"},
	})
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	areas := areasByCode(report)

	access := areas["CC6.1"]
	if access.TotalEvents != 3 {
		t.Errorf("CC6.1 TotalEvents=%d, want 3", access.TotalEvents)
	}
	if access.DistinctActors != 3 {
		t.Errorf("CC6.1 DistinctActors=%d, want 3 (alice,bob,eve)", access.DistinctActors)
	}
	if access.ByOutcome["success"] != 2 || access.ByOutcome["failure"] != 1 {
		t.Errorf("CC6.1 ByOutcome=%v, want success=2 failure=1", access.ByOutcome)
	}

	if got := areas["CC6.7"].TotalEvents; got != 1 {
		t.Errorf("CC6.7 TotalEvents=%d, want 1", got)
	}
	if got := areas["CC6.6"].TotalEvents; got != 1 {
		t.Errorf("CC6.6 TotalEvents=%d, want 1", got)
	}
	if got := areas["CC6.3"].TotalEvents; got != 1 {
		t.Errorf("CC6.3 TotalEvents=%d, want 1", got)
	}
	if got := areas["CC7.2"].TotalEvents; got != 0 {
		t.Errorf("CC7.2 TotalEvents=%d, want 0 (no anomaly events seeded)", got)
	}
	if report.Uncategorized.TotalEvents != 0 {
		t.Errorf("Uncategorized.TotalEvents=%d, want 0", report.Uncategorized.TotalEvents)
	}
}

// TestBuildSOC2Report_NamedAreaVocabularyIsAlwaysPresent proves a named
// area's EventTypes vocabulary is populated from controlAreaDefs even
// when the area saw zero events in this bundle — a report must always
// document what each area COVERS, not just what it observed.
func TestBuildSOC2Report_NamedAreaVocabularyIsAlwaysPresent(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, nil)
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	access := areasByCode(report)["CC6.1"]
	if access.TotalEvents != 0 {
		t.Fatalf("TotalEvents=%d, want 0 on an empty bundle", access.TotalEvents)
	}
	if len(access.EventTypes) == 0 {
		t.Fatal("CC6.1 EventTypes should list its static vocabulary even with zero observed events")
	}
	found := false
	for _, et := range access.EventTypes {
		if et == audit.EventLogin {
			found = true
		}
	}
	if !found {
		t.Errorf("CC6.1 EventTypes=%v, want it to include EventLogin", access.EventTypes)
	}
}

// TestBuildSOC2Report_UncategorizedCatchesUnmappedType proves an event
// whose Type matches NO controlAreaDefs entry lands in Uncategorized
// rather than being silently dropped or mis-bucketed, and that its
// EventTypes lists only what was actually OBSERVED (not a static
// vocabulary, unlike a named area).
func TestBuildSOC2Report_UncategorizedCatchesUnmappedType(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, []audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
		{Type: "custom_operator_event", Outcome: audit.OutcomeSuccess, ActorID: "svc"},
		{Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
	})
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	if report.Uncategorized.TotalEvents != 2 {
		t.Fatalf("Uncategorized.TotalEvents=%d, want 2 (custom_operator_event + token_issued)", report.Uncategorized.TotalEvents)
	}
	want := map[audit.EventType]bool{"custom_operator_event": true, audit.EventTokenIssued: true}
	if len(report.Uncategorized.EventTypes) != len(want) {
		t.Fatalf("Uncategorized.EventTypes=%v, want 2 distinct types", report.Uncategorized.EventTypes)
	}
	for _, et := range report.Uncategorized.EventTypes {
		if !want[et] {
			t.Errorf("unexpected type in Uncategorized.EventTypes: %s", et)
		}
	}
	// Sum invariant: every observed event lands in EXACTLY one bucket.
	sum := report.Uncategorized.TotalEvents
	for _, a := range report.ControlAreas {
		sum += a.TotalEvents
	}
	if sum != bundle.EventCount {
		t.Errorf("sum(areas)+Uncategorized=%d, want bundle.EventCount=%d", sum, bundle.EventCount)
	}
}

func TestBuildSOC2Report_PreservesChainMetadata(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, []audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "bob"},
	})
	report, err := auditreport.BuildSOC2Report(bundle, true)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	if report.Chain.EventCount != bundle.EventCount {
		t.Errorf("Chain.EventCount=%d, want %d", report.Chain.EventCount, bundle.EventCount)
	}
	if report.Chain.BoundaryPrevHash != bundle.BoundaryPrevHash {
		t.Errorf("Chain.BoundaryPrevHash=%q, want %q", report.Chain.BoundaryPrevHash, bundle.BoundaryPrevHash)
	}
	if report.Chain.HeadHash != bundle.HeadHash {
		t.Errorf("Chain.HeadHash=%q, want %q", report.Chain.HeadHash, bundle.HeadHash)
	}
	if report.Chain.Contiguous != bundle.Contiguous {
		t.Errorf("Chain.Contiguous=%t, want %t", report.Chain.Contiguous, bundle.Contiguous)
	}
	if report.Chain.BundleFormat != bundle.FormatVersion {
		t.Errorf("Chain.BundleFormat=%d, want %d", report.Chain.BundleFormat, bundle.FormatVersion)
	}
	if !report.Chain.Verified {
		t.Error("Chain.Verified should reflect the chainVerified argument (true)")
	}
}

// TestBuildSOC2Report_NeverEmbedsRawEvents guards the "aggregate counts,
// never echo raw event payloads" invariant at the JSON level: a report
// marshaled to JSON must not carry an "events" array anywhere, even
// though its source ExportBundle does.
func TestBuildSOC2Report_NeverEmbedsRawEvents(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, []audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice", Reason: "sensitive-detail"},
	})
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), `"events"`) {
		t.Errorf("report JSON must not embed a raw events array:\n%s", raw)
	}
	if strings.Contains(string(raw), "sensitive-detail") {
		t.Errorf("report JSON must not echo raw event field content:\n%s", raw)
	}
}

func TestBuildSOC2Report_NilBundleErrors(t *testing.T) {
	t.Parallel()
	if _, err := auditreport.BuildSOC2Report(nil, false); err == nil {
		t.Error("nil bundle should error")
	}
}

func TestBuildSOC2Report_EmptyBundleIsNoopNotError(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, nil)
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report on empty bundle: %v", err)
	}
	for _, a := range report.ControlAreas {
		if a.TotalEvents != 0 {
			t.Errorf("area %s TotalEvents=%d, want 0", a.Code, a.TotalEvents)
		}
	}
	if report.Uncategorized.TotalEvents != 0 {
		t.Errorf("Uncategorized.TotalEvents=%d, want 0", report.Uncategorized.TotalEvents)
	}
}

func TestBuildSOC2Report_MappingDisclaimerAlwaysPresent(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, nil)
	report, err := auditreport.BuildSOC2Report(bundle, false)
	if err != nil {
		t.Fatalf("BuildSOC2Report: %v", err)
	}
	if report.MappingDisclaimer != auditreport.MappingDisclaimer {
		t.Error("MappingDisclaimer must equal the fixed package constant")
	}
	if report.MappingDisclaimer == "" {
		t.Fatal("MappingDisclaimer must never be empty")
	}
	for _, want := range []string{"NOT a vetted SOC2", "illustrative"} {
		if !strings.Contains(report.MappingDisclaimer, want) {
			t.Errorf("MappingDisclaimer missing %q: %s", want, report.MappingDisclaimer)
		}
	}
}

func TestVerifyAndBuildSOC2Report_HappyPath(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, []audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "bob"},
	})
	report, err := auditreport.VerifyAndBuildSOC2Report(bundle)
	if err != nil {
		t.Fatalf("VerifyAndBuildSOC2Report: %v", err)
	}
	if !report.Chain.Verified {
		t.Error("Chain.Verified should be true on an untampered bundle")
	}
}

// TestVerifyAndBuildSOC2Report_FailsClosedOnTamperedBundle mutates one
// exported event's Reason post-hoc (mirrors chainer_test.go's tamper
// pattern) and asserts VerifyAndBuildSOC2Report returns a non-nil error
// AND a nil report — never a partial report handed to a caller as if it
// were usable evidence.
func TestVerifyAndBuildSOC2Report_FailsClosedOnTamperedBundle(t *testing.T) {
	t.Parallel()
	bundle := recordBundle(t, []audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "alice"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "bob"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, ActorID: "carol"},
	})
	bundle.Events[1].Reason = "tampered"

	report, err := auditreport.VerifyAndBuildSOC2Report(bundle)
	if err == nil {
		t.Fatal("VerifyAndBuildSOC2Report accepted a tampered bundle")
	}
	if report != nil {
		t.Fatal("VerifyAndBuildSOC2Report must return a nil report on verify failure")
	}
}

func TestVerifyAndBuildSOC2Report_NilBundleErrors(t *testing.T) {
	t.Parallel()
	if _, err := auditreport.VerifyAndBuildSOC2Report(nil); err == nil {
		t.Error("nil bundle should error")
	}
}
