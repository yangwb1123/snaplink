package audit_test

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

func syslogRecord(t *testing.T, facility int, hostname, appName string, inner audit.Formatter, e *audit.Event) string {
	t.Helper()
	var buf strings.Builder
	sink := audit.NewSyslogSink(&buf, facility, hostname, appName, inner)
	if err := sink.Record(context.Background(), e); err != nil {
		t.Fatalf("Record: %v", err)
	}
	return strings.TrimRight(buf.String(), "\n")
}

// syslog5424Header captures PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME,
// PROCID, MSGID, and STRUCTURED-DATA per RFC 5424 section 6.
var syslog5424Header = regexp.MustCompile(
	`^<(\d+)>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*\]) (.*)$`)

// TestSyslog_GoldenRFC5424Structure covers a representative event with
// Metadata, asserting the full RFC 5424 header shape (PRI/VERSION/
// TIMESTAMP/HOSTNAME/APP-NAME/PROCID/MSGID/STRUCTURED-DATA/MSG) with the
// default JSON inner formatter.
func TestSyslog_GoldenRFC5424Structure(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	line := syslogRecord(t, 10, "sso-host-1", "sso-server", nil, &audit.Event{
		Type:      audit.EventAccountLocked,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: ts,
		Metadata:  map[string]string{"attempts": "5"},
	})

	m := syslog5424Header.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line does not match RFC 5424 header shape: %q", line)
	}
	pri, verTS, hostname, appName, _, msgID, sd, msg := m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8]

	// facility(10)*8 + syslog severity for the account_locked override
	// (High -> 3) = 83.
	if pri != "83" {
		t.Errorf("PRI = %s, want 83", pri)
	}
	if _, err := time.Parse(time.RFC3339Nano, verTS); err != nil {
		t.Errorf("TIMESTAMP %q not RFC3339: %v", verTS, err)
	}
	if hostname != "sso-host-1" {
		t.Errorf("HOSTNAME = %q, want sso-host-1", hostname)
	}
	if appName != "sso-server" {
		t.Errorf("APP-NAME = %q, want sso-server", appName)
	}
	if msgID != "account_locked" {
		t.Errorf("MSGID = %q, want account_locked", msgID)
	}
	if sd != `[audit attempts="5"]` {
		t.Errorf("STRUCTURED-DATA = %q, want [audit attempts=\"5\"]", sd)
	}
	var inner map[string]any
	if err := json.Unmarshal([]byte(msg), &inner); err != nil {
		t.Fatalf("MSG not valid JSON (default inner formatter): %v\n%s", err, msg)
	}
	if inner["type"] != string(audit.EventAccountLocked) {
		t.Errorf("MSG.type = %v, want account_locked", inner["type"])
	}
}

// TestSyslog_NoMetadataIsNilValue proves an empty Metadata map renders
// STRUCTURED-DATA as the RFC 5424 NILVALUE "-", not an empty "[audit]".
func TestSyslog_NoMetadataIsNilValue(t *testing.T) {
	t.Parallel()
	line := syslogRecord(t, 10, "host", "app", nil, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess})
	m := syslog5424Header.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line does not match RFC 5424 header shape: %q", line)
	}
	if m[7] != "-" {
		t.Errorf("STRUCTURED-DATA = %q, want NILVALUE -", m[7])
	}
}

// TestSyslog_EmptyHostnameAppNameUseNilValue proves empty hostname/appName
// configuration falls back to the RFC 5424 NILVALUE rather than an empty
// field (which would corrupt the space-delimited header).
func TestSyslog_EmptyHostnameAppNameUseNilValue(t *testing.T) {
	t.Parallel()
	line := syslogRecord(t, 10, "", "", nil, &audit.Event{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess})
	m := syslog5424Header.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line does not match RFC 5424 header shape: %q", line)
	}
	if m[3] != "-" || m[4] != "-" {
		t.Errorf("HOSTNAME/APP-NAME = %q/%q, want -/-", m[3], m[4])
	}
}

// TestSyslog_StructuredDataEscaping is the format-spec-fidelity test for
// RFC 5424 section 6.3.3: '"' and '\' in a Metadata value must be
// backslash-escaped inside the SD-PARAM value. (The ']' case — also
// escaped per the same rule — is covered directly against the unexported
// builder in auditsink's own white-box test, since a ']' inside MSG, e.g.
// from the default JSON formatter re-emitting the same raw metadata value,
// makes black-box regex parsing of the full line ambiguous.)
func TestSyslog_StructuredDataEscaping(t *testing.T) {
	t.Parallel()
	line := syslogRecord(t, 10, "host", "app", nil, &audit.Event{
		Type:     audit.EventLogin,
		Outcome:  audit.OutcomeSuccess,
		Metadata: map[string]string{"note": `has "quotes" \backslash`},
	})
	m := syslog5424Header.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line does not match RFC 5424 header shape: %q", line)
	}
	want := `[audit note="has \"quotes\" \\backslash"]`
	if m[7] != want {
		t.Errorf("STRUCTURED-DATA = %q, want %q", m[7], want)
	}
}

// TestSyslog_ComposesCEFOverSyslog proves FormatSyslog wraps an arbitrary
// inner Formatter (the "CEF-over-syslog" enterprise pattern) rather than
// being hardcoded to JSON.
func TestSyslog_ComposesCEFOverSyslog(t *testing.T) {
	t.Parallel()
	line := syslogRecord(t, 10, "host", "app", audit.FormatCEF("Snaplink", "SSO", "1.0"), &audit.Event{
		Type: audit.EventLogin, Outcome: audit.OutcomeSuccess,
	})
	m := syslog5424Header.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line does not match RFC 5424 header shape: %q", line)
	}
	if !strings.HasPrefix(m[8], "CEF:0|Snaplink|SSO|1.0|login|") {
		t.Errorf("MSG = %q, want a CEF-formatted payload", m[8])
	}
}

// TestSyslog_UnknownEventTypeMsgIDFallsBack proves MSGID falls back to the
// NILVALUE for the degenerate empty-type case (never emits a blank field).
func TestSyslog_UnknownEventTypeMsgIDFallsBack(t *testing.T) {
	t.Parallel()
	line := syslogRecord(t, 10, "host", "app", nil, &audit.Event{Type: "", Outcome: audit.OutcomeSuccess})
	m := syslog5424Header.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line does not match RFC 5424 header shape: %q", line)
	}
	if m[6] != "-" {
		t.Errorf("MSGID = %q, want NILVALUE -", m[6])
	}
}
