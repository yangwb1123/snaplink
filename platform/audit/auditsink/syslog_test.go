package auditsink

import (
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// TestSyslogStructuredData_EscapesReservedCharacters is the direct
// unit-level counterpart to platform/audit's black-box syslog test —
// exercised here against the unexported builder so the ']' case (awkward
// to isolate in a black-box regex over a full composed line, see the
// black-box test's comment) gets precise coverage.
func TestSyslogStructuredData_EscapesReservedCharacters(t *testing.T) {
	t.Parallel()
	got := syslogStructuredData(map[string]string{
		"note": `has "quotes" \backslash and ] bracket`,
	})
	want := `[audit note="has \"quotes\" \\backslash and \] bracket"]`
	if got != want {
		t.Errorf("syslogStructuredData() = %q, want %q", got, want)
	}
}

// TestSyslogStructuredData_SanitizesParamName proves a pathological
// Metadata key (one containing characters RFC 5424 PARAM-NAME excludes
// outright: '=', SP, ']', '"') is sanitized rather than left to corrupt
// the structured-data syntax.
func TestSyslogStructuredData_SanitizesParamName(t *testing.T) {
	t.Parallel()
	got := syslogStructuredData(map[string]string{`bad=name]here`: "v"})
	want := `[audit bad_name_here="v"]`
	if got != want {
		t.Errorf("syslogStructuredData() = %q, want %q", got, want)
	}
}

// TestSyslogStructuredData_EmptyIsNilValue proves the RFC 5424 NILVALUE "-"
// is used for empty Metadata, never an empty "[audit]" element.
func TestSyslogStructuredData_EmptyIsNilValue(t *testing.T) {
	t.Parallel()
	if got := syslogStructuredData(nil); got != "-" {
		t.Errorf("syslogStructuredData(nil) = %q, want -", got)
	}
	if got := syslogStructuredData(map[string]string{}); got != "-" {
		t.Errorf("syslogStructuredData({}) = %q, want -", got)
	}
}

// TestSyslogStructuredData_SortedKeys proves deterministic ordering across
// multiple entries (map iteration order is otherwise randomized).
func TestSyslogStructuredData_SortedKeys(t *testing.T) {
	t.Parallel()
	got := syslogStructuredData(map[string]string{"zzz": "1", "aaa": "2"})
	want := `[audit aaa="2" zzz="1"]`
	if got != want {
		t.Errorf("syslogStructuredData() = %q, want %q", got, want)
	}
}

// TestSyslogMsgID_TruncatesAndFallsBack covers MSGID's 32-char RFC 5424
// limit and the NILVALUE fallback for an empty type.
func TestSyslogMsgID_TruncatesAndFallsBack(t *testing.T) {
	t.Parallel()
	if got := syslogMsgID(""); got != "-" {
		t.Errorf("syslogMsgID(\"\") = %q, want -", got)
	}
	long := "a_very_long_custom_event_type_name_that_exceeds_thirty_two_characters"
	got := syslogMsgID(auditspi.EventType(long))
	if len(got) != 32 {
		t.Errorf("syslogMsgID(long) len = %d, want 32", len(got))
	}
}
