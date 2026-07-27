package selfservicecore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/shared/core"
)

// newTestCtx builds a real core.HandlerContext for RecordSelfErase (it only
// reads ctx.Request()).
func newTestCtx() core.HandlerContext {
	req := httptest.NewRequest(http.MethodPost, "/me/account/erase", strings.NewReader(""))
	return core.NewContext(httptest.NewRecorder(), req)
}

func TestRecordSelfErase_NilAuditorIsNoOp(t *testing.T) {
	t.Parallel()
	// Exercises the nil-Auditor early return — must not panic.
	RecordSelfErase(nilAuditorDeps{}, newTestCtx(), "user-1", &compliance.Report{UserID: "user-1"})
}

func TestRecordSelfErase_RecordsExpectedMetadata(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	report := &compliance.Report{
		UserID: "user-1", DryRun: false, SessionsDestroyed: 2,
		RefreshTokensDeleted: 3, UserDeleted: true,
	}

	RecordSelfErase(auditorDeps{auditor: rec}, newTestCtx(), "user-1", report)

	events, err := sink.Query(t.Context(), audit.Query{})
	if err != nil {
		t.Fatalf("query sink: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	evt := events[0]
	if evt.Type != audit.EventSubjectSelfErased || evt.Outcome != audit.OutcomeSuccess {
		t.Errorf("type=%v outcome=%v, want EventSubjectSelfErased/Success", evt.Type, evt.Outcome)
	}
	if evt.ActorID != "user-1" {
		t.Errorf("ActorID = %q, want user-1", evt.ActorID)
	}
	if evt.Metadata["sessions_destroyed"] != "2" || evt.Metadata["refresh_tokens_deleted"] != "3" {
		t.Errorf("unexpected metadata: %+v", evt.Metadata)
	}
	if evt.Metadata["user_deleted"] != "true" {
		t.Errorf("user_deleted metadata = %q, want true", evt.Metadata["user_deleted"])
	}
}

func TestRecordSelfErase_ReportErrorMarksFailure(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	report := &compliance.Report{UserID: "user-1", Errors: []error{errBoom{}}}

	RecordSelfErase(auditorDeps{auditor: rec}, newTestCtx(), "user-1", report)

	events, _ := sink.Query(t.Context(), audit.Query{})
	if len(events) != 1 || events[0].Outcome != audit.OutcomeFailure {
		t.Fatalf("expected a single failure-outcome event, got %+v", events)
	}
}

// nilAuditorDeps / auditorDeps are minimal Deps stand-ins covering ONLY the
// single accessor RecordSelfErase calls (Auditor()); every other Deps method
// panics if invoked, which would immediately fail the test — an intentional
// guard that RecordSelfErase never reaches beyond Auditor().
type nilAuditorDeps struct{ Deps }

func (nilAuditorDeps) Auditor() *audit.Recorder { return nil }

type auditorDeps struct {
	Deps
	auditor *audit.Recorder
}

func (d auditorDeps) Auditor() *audit.Recorder { return d.auditor }

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
