package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/snaplink/sso/platform/audit"
)

func TestNewTraceID_LengthAndHex(t *testing.T) {
	tr := audit.NewTracer()
	for range 50 {
		id := tr.NewTraceID()
		if len(id) != audit.TraceIDBytes*2 {
			t.Fatalf("trace id length = %d, want %d", len(id), audit.TraceIDBytes*2)
		}
		if strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("trace id has non-hex chars: %q", id)
		}
		if strings.Trim(id, "0") == "" {
			t.Fatalf("trace id must not be all-zero")
		}
	}
}

func TestNewSpanID_LengthAndHex(t *testing.T) {
	tr := audit.NewTracer()
	for range 50 {
		id := tr.NewSpanID()
		if len(id) != audit.SpanIDBytes*2 {
			t.Fatalf("span id length = %d, want %d", len(id), audit.SpanIDBytes*2)
		}
		if strings.Trim(id, "0") == "" {
			t.Fatalf("span id must not be all-zero")
		}
	}
}

func TestNewTraceID_Uniqueness(t *testing.T) {
	tr := audit.NewTracer()
	seen := make(map[string]struct{})
	for range 1000 {
		id := tr.NewTraceID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate trace id: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestFormatTraceparent(t *testing.T) {
	tr := audit.NewTracer()
	tc := audit.TraceContext{
		TraceID: "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:  "00f067aa0ba902b7",
		Flags:   audit.FlagSampled,
	}
	got := tr.FormatTraceparent(tc)
	want := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFormatTraceparent_ZeroFlagsPadded(t *testing.T) {
	tr := audit.NewTracer()
	tc := audit.TraceContext{
		TraceID: "11111111111111111111111111111111",
		SpanID:  "2222222222222222",
		Flags:   0,
	}
	got := tr.FormatTraceparent(tc)
	if !strings.HasSuffix(got, "-00") {
		t.Fatalf("flags should be zero-padded to two hex chars; got %q", got)
	}
}

func TestParseTraceparent_Valid(t *testing.T) {
	tr := audit.NewTracer()
	tc, err := tr.ParseTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tc.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("TraceID = %q", tc.TraceID)
	}
	if tc.SpanID != "00f067aa0ba902b7" {
		t.Errorf("SpanID = %q", tc.SpanID)
	}
	if !tc.IsSampled() {
		t.Errorf("Sampled flag not set")
	}
	if !tc.IsValid() {
		t.Errorf("parsed context should be Valid()")
	}
}

func TestParseTraceparent_Malformed(t *testing.T) {
	tr := audit.NewTracer()
	cases := []string{
		"",
		"only-three-parts-here",
		"01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // wrong version
		"00-not-hex-here-here-here-00f067aa0ba902b7-01",
		"00-4bf92f3577b34da6a3ce929d0e0e4736-tooshort-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // all-zero trace
		"00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // all-zero span
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-1",  // 1-char flags
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz", // flags not hex
		"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
	}
	for _, s := range cases {
		_, err := tr.ParseTraceparent(s)
		if !errors.Is(err, audit.ErrInvalidTraceparent) {
			t.Errorf("ParseTraceparent(%q) should fail, got err=%v", s, err)
		}
	}
}

func TestParseFormat_Roundtrip(t *testing.T) {
	tr := audit.NewTracer()
	tc := audit.TraceContext{
		TraceID: tr.NewTraceID(),
		SpanID:  tr.NewSpanID(),
		Flags:   audit.FlagSampled,
	}
	parsed, err := tr.ParseTraceparent(tr.FormatTraceparent(tc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.TraceID != tc.TraceID || parsed.SpanID != tc.SpanID || parsed.Flags != tc.Flags {
		t.Fatalf("roundtrip mismatch: in=%+v out=%+v", tc, parsed)
	}
}

func TestStartChild_NoParentStartsNewTrace(t *testing.T) {
	tr := audit.NewTracer()
	child := tr.StartChild(audit.TraceContext{})

	if !child.IsValid() {
		t.Fatalf("root child should be valid: %+v", child)
	}
	if child.ParentSpanID != "" {
		t.Errorf("root child must have empty ParentSpanID; got %q", child.ParentSpanID)
	}
	if !child.IsSampled() {
		t.Errorf("root child should default to sampled")
	}
}

func TestStartChild_PreservesTraceAndChainsSpan(t *testing.T) {
	tr := audit.NewTracer()
	parent := audit.TraceContext{
		TraceID: tr.NewTraceID(),
		SpanID:  tr.NewSpanID(),
		Flags:   audit.FlagSampled,
	}
	child := tr.StartChild(parent)

	if child.TraceID != parent.TraceID {
		t.Errorf("trace id should be inherited; parent=%s child=%s", parent.TraceID, child.TraceID)
	}
	if child.ParentSpanID != parent.SpanID {
		t.Errorf("parent span id mismatch: %s vs %s", child.ParentSpanID, parent.SpanID)
	}
	if child.SpanID == parent.SpanID {
		t.Errorf("child must get a fresh span id; got same %q", child.SpanID)
	}
	if child.Flags != parent.Flags {
		t.Errorf("flags should be inherited")
	}
}

func TestStartChild_InvalidParentIsTreatedAsRoot(t *testing.T) {
	tr := audit.NewTracer()
	// Half-built parent (TraceID set, SpanID empty) is invalid.
	bad := audit.TraceContext{TraceID: tr.NewTraceID()}
	child := tr.StartChild(bad)

	if child.TraceID == bad.TraceID {
		t.Errorf("invalid parent should not propagate its trace id")
	}
	if child.ParentSpanID != "" {
		t.Errorf("invalid parent should yield rootless child; got parent=%q", child.ParentSpanID)
	}
}

func TestTraceContext_IsValid(t *testing.T) {
	if (audit.TraceContext{}).IsValid() {
		t.Error("zero context should not be Valid()")
	}
	if (audit.TraceContext{TraceID: "abc", SpanID: "0123456789abcdef"}).IsValid() {
		t.Error("short trace id should fail IsValid()")
	}
	tr := audit.NewTracer()
	if !(audit.TraceContext{TraceID: tr.NewTraceID(), SpanID: tr.NewSpanID()}).IsValid() {
		t.Error("correctly-sized IDs should pass IsValid()")
	}
}
