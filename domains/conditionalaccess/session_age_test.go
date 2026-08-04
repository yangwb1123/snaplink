package conditionalaccess

import (
	"testing"
	"time"
)

func TestSessionAndAuthenticationAgeConditions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		cond Conditions
		ac   AccessContext
		want Verdict
	}{
		{"old session", Conditions{SessionAgeSeconds: 3600}, AccessContext{Now: now, SessionCreatedAt: now.Add(-time.Hour)}, VerdictDeny},
		{"young session", Conditions{SessionAgeSeconds: 3600}, AccessContext{Now: now, SessionCreatedAt: now.Add(-59 * time.Minute)}, VerdictAllow},
		{"missing session signal", Conditions{SessionAgeSeconds: 1}, AccessContext{Now: now}, VerdictAllow},
		{"old authentication", Conditions{AuthenticationAgeSeconds: 7200}, AccessContext{Now: now, AuthTime: now.Add(-2 * time.Hour)}, VerdictDeny},
		{"future authentication", Conditions{AuthenticationAgeSeconds: 1}, AccessContext{Now: now, AuthTime: now.Add(time.Minute)}, VerdictAllow},
		{"concurrent session excess", Conditions{MaxConcurrentSessions: 2}, AccessContext{ConcurrentSessions: 3, ConcurrentSessionsKnown: true}, VerdictDeny},
		{"concurrent session at ceiling", Conditions{MaxConcurrentSessions: 2}, AccessContext{ConcurrentSessions: 2, ConcurrentSessionsKnown: true}, VerdictAllow},
		{"missing concurrent count", Conditions{MaxConcurrentSessions: 2}, AccessContext{ConcurrentSessions: 3}, VerdictAllow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy := Policy{Name: "age", Enabled: true, Conditions: tc.cond, Actions: Actions{Deny: true}}
			if got := Decide(Config{}, []Policy{policy}, tc.ac).Verdict; got != tc.want {
				t.Fatalf("verdict = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPolicyValidateRejectsNegativeAge(t *testing.T) {
	t.Parallel()
	policy := Policy{Name: "bad-age", Conditions: Conditions{AuthenticationAgeSeconds: -1}}
	if err := policy.Validate(); err == nil {
		t.Fatal("negative authentication age should be rejected")
	}
}
