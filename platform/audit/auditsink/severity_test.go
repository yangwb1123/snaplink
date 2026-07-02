package auditsink

import (
	"testing"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

// TestEventSeverity_OutcomeAndOverrides is the severity-projection table
// test: overrides win regardless of outcome; absent-from-override types
// fall back to outcome (failure=Medium, success=Info).
func TestEventSeverity_OutcomeAndOverrides(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		event *auditspi.Event
		want  severityLevel
	}{
		{"success login, no override -> info", &auditspi.Event{Type: auditspi.EventLogin, Outcome: auditspi.OutcomeSuccess}, severityInfo},
		{"failed login, no override -> medium", &auditspi.Event{Type: auditspi.EventLoginFailure, Outcome: auditspi.OutcomeFailure}, severityMedium},
		{"account locked overridden high regardless of outcome", &auditspi.Event{Type: auditspi.EventAccountLocked, Outcome: auditspi.OutcomeSuccess}, severityHigh},
		{"refresh reuse overridden critical", &auditspi.Event{Type: auditspi.EventRefreshTokenReuse, Outcome: auditspi.OutcomeFailure}, severityCritical},
		{"client access overridden info even on failure", &auditspi.Event{Type: auditspi.EventClientAccess, Outcome: auditspi.OutcomeFailure}, severityInfo},
		{"tenant tokens revoked overridden medium on success", &auditspi.Event{Type: auditspi.EventTenantTokensRevoked, Outcome: auditspi.OutcomeSuccess}, severityMedium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := eventSeverity(tc.event); got != tc.want {
				t.Errorf("eventSeverity() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSeverityProjections_MonotonicAcrossScales proves the ONE shared scale
// is consistently ordered when projected into each wire format: as
// severityLevel increases (more severe), CEF/OCSF increase (higher =
// worse) while syslog decreases (lower = worse, RFC 5424 Table 2).
func TestSeverityProjections_MonotonicAcrossScales(t *testing.T) {
	t.Parallel()
	levels := []severityLevel{severityInfo, severityLow, severityMedium, severityHigh, severityCritical}
	for i := 1; i < len(levels); i++ {
		prev, cur := levels[i-1], levels[i]
		if toCEFSeverity(cur) <= toCEFSeverity(prev) {
			t.Errorf("toCEFSeverity(%v)=%d not > toCEFSeverity(%v)=%d", cur, toCEFSeverity(cur), prev, toCEFSeverity(prev))
		}
		if toOCSFSeverityID(cur) <= toOCSFSeverityID(prev) {
			t.Errorf("toOCSFSeverityID(%v)=%d not > toOCSFSeverityID(%v)=%d", cur, toOCSFSeverityID(cur), prev, toOCSFSeverityID(prev))
		}
		if toSyslogSeverity(cur) >= toSyslogSeverity(prev) {
			t.Errorf("toSyslogSeverity(%v)=%d not < toSyslogSeverity(%v)=%d (lower=more severe)", cur, toSyslogSeverity(cur), prev, toSyslogSeverity(prev))
		}
	}
}

// TestSeverityProjections_WithinSpecRanges pins each projection to its
// wire format's valid numeric range (CEF 0-10, OCSF severity_id 1-6,
// syslog 0-7) so a future scale tweak can't silently drift out of range.
func TestSeverityProjections_WithinSpecRanges(t *testing.T) {
	t.Parallel()
	for lvl := severityInfo; lvl <= severityCritical; lvl++ {
		if cef := toCEFSeverity(lvl); cef < 0 || cef > 10 {
			t.Errorf("toCEFSeverity(%v) = %d out of CEF's 0-10 range", lvl, cef)
		}
		if ocsf := toOCSFSeverityID(lvl); ocsf < 1 || ocsf > 6 {
			t.Errorf("toOCSFSeverityID(%v) = %d out of OCSF's 1-6 range", lvl, ocsf)
		}
		if sys := toSyslogSeverity(lvl); sys < 0 || sys > 7 {
			t.Errorf("toSyslogSeverity(%v) = %d out of syslog's 0-7 range", lvl, sys)
		}
	}
}
