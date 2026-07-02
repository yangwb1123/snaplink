package audit_test

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

func cefRecord(t *testing.T, e *audit.Event) string {
	t.Helper()
	var buf strings.Builder
	sink := audit.NewCEFSink(&buf, "Snaplink", "SSO", "1.2.3")
	if err := sink.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// TestCEF_GoldenRepresentativeEvent covers a fully-populated event,
// asserting the CEF header shape and every standard extension key.
func TestCEF_GoldenRepresentativeEvent(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	line := cefRecord(t, &audit.Event{
		Type:      audit.EventLoginFailure,
		Outcome:   audit.OutcomeFailure,
		Timestamp: ts,
		ActorID:   "alice",
		ActorIP:   "198.51.100.7",
		UserAgent: "curl/8.0",
		TenantID:  "acme",
		ClientID:  "client-1",
		SessionID: "sess-1",
		RequestID: "req-1",
		TraceID:   "trace-1",
		TokenID:   "tok-1",
		Reason:    "bad password",
	})

	wantHeader := "CEF:0|Snaplink|SSO|1.2.3|login_failure|User Login Failure|5|"
	if !strings.HasPrefix(line, wantHeader) {
		t.Fatalf("header mismatch:\n got: %s\nwant prefix: %s", line, wantHeader)
	}
	ext := strings.TrimPrefix(line, wantHeader)
	for _, want := range []string{
		"rt=" + fmtMillis(ts),
		"outcome=failure",
		"src=198.51.100.7",
		"suser=alice",
		"requestClientApplication=curl/8.0",
		"msg=bad password",
		"cs1Label=TenantID", "cs1=acme",
		"cs2Label=ClientID", "cs2=client-1",
		"cs3Label=SessionID", "cs3=sess-1",
		"cs4Label=RequestID", "cs4=req-1",
		"cs5Label=TraceID", "cs5=trace-1",
		"cs6Label=TokenID", "cs6=tok-1",
	} {
		if !strings.Contains(ext, want) {
			t.Errorf("extension missing %q in %q", want, ext)
		}
	}
}

// TestCEF_EmptyFieldsOmitted proves optional extension keys are omitted
// (not emitted blank) when the source Event field is empty.
func TestCEF_EmptyFieldsOmitted(t *testing.T) {
	t.Parallel()
	line := cefRecord(t, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess})

	if !strings.HasPrefix(line, "CEF:0|Snaplink|SSO|1.2.3|login|User Login|1|") {
		t.Fatalf("unexpected header: %s", line)
	}
	for _, absent := range []string{"src=", "suser=", "requestClientApplication=", "msg=", "cs1", "cs2", "cs3", "cs4", "cs5", "cs6"} {
		if strings.Contains(line, absent) {
			t.Errorf("expected %q absent from empty-field event, got %q", absent, line)
		}
	}
}

// TestCEF_UnknownEventTypeFallsBack exercises the humanized fallback for a
// type outside the curated table.
func TestCEF_UnknownEventTypeFallsBack(t *testing.T) {
	t.Parallel()
	line := cefRecord(t, &audit.Event{Type: audit.EventType("operator_custom_event"), Outcome: audit.OutcomeSuccess})
	if !strings.HasPrefix(line, "CEF:0|Snaplink|SSO|1.2.3|operator_custom_event|Operator Custom Event|1|") {
		t.Fatalf("unexpected fallback header: %s", line)
	}
}

// TestCEF_EscapesMetadataAndReservedCharacters is the format-spec-fidelity
// test: a Reason and Metadata value carrying '=', '|', and '\' must come
// out escaped, and metadata pairs are sorted for determinism.
func TestCEF_EscapesMetadataAndReservedCharacters(t *testing.T) {
	t.Parallel()
	line := cefRecord(t, &audit.Event{
		Type:    audit.EventLogin,
		Outcome: audit.OutcomeSuccess,
		Reason:  `has = and | and \ chars`,
		Metadata: map[string]string{
			"zzz":    `back\slash`,
			"target": "a=b|c",
		},
	})

	if !strings.Contains(line, `msg=has \= and | and \\ chars`) {
		t.Errorf("Reason not escaped correctly: %s", line)
	}
	if !strings.Contains(line, `meta.target=a\=b|c`) {
		t.Errorf("metadata value not escaped correctly: %s", line)
	}
	if !strings.Contains(line, `meta.zzz=back\\slash`) {
		t.Errorf("metadata backslash not escaped correctly: %s", line)
	}
	// Sorted: "target" before "zzz".
	if strings.Index(line, "meta.target=") > strings.Index(line, "meta.zzz=") {
		t.Errorf("metadata keys not sorted: %s", line)
	}
}

func fmtMillis(ts time.Time) string {
	return strconv.FormatInt(ts.UnixMilli(), 10)
}
