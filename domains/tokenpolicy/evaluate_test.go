package tokenpolicy

import (
	"testing"
	"time"
)

// TestEvaluate_TTLClampDownwardOnly is the core max_ttl invariant: a matching
// MaxTTL only ever REDUCES the requested lifetime (or fills in a ceiling for an
// unset one), and NEVER raises a client-configured TTL.
func TestEvaluate_TTLClampDownwardOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		requested  time.Duration
		maxTTL     time.Duration
		wantEffTTL time.Duration
	}{
		{"no policy leaves requested", time.Hour, 0, time.Hour},
		{"clamps down when max below requested", time.Hour, 15 * time.Minute, 15 * time.Minute},
		{"never raises a configured ttl", time.Hour, 2 * time.Hour, time.Hour},
		{"equal ttl is a no-op", time.Hour, time.Hour, time.Hour},
		{"unset requested takes the ceiling", 0, 15 * time.Minute, 15 * time.Minute},
		{"unset requested + no max stays default", 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var policies []Policy
			if tc.maxTTL > 0 {
				policies = []Policy{{Name: "p", MaxTTL: tc.maxTTL}}
			}
			got := Evaluate(PolicyInput{ClientID: "c", RequestedTTL: tc.requested, Kind: KindAccess}, policies)
			if got.EffectiveTTL != tc.wantEffTTL {
				t.Fatalf("EffectiveTTL = %v, want %v", got.EffectiveTTL, tc.wantEffTTL)
			}
			if got.Deny {
				t.Fatalf("unexpected deny: %+v", got)
			}
		})
	}
}

// TestEvaluate_TTLStrictestWins proves overlapping MaxTTL policies combine to
// the SMALLEST (strictest) positive ceiling — rules only ever tighten.
func TestEvaluate_TTLStrictestWins(t *testing.T) {
	t.Parallel()
	policies := []Policy{
		{Name: "loose", MaxTTL: 30 * time.Minute},
		{Name: "tight", MaxTTL: 5 * time.Minute},
	}
	got := Evaluate(PolicyInput{ClientID: "c", RequestedTTL: time.Hour, Kind: KindAccess}, policies)
	if got.EffectiveTTL != 5*time.Minute {
		t.Fatalf("EffectiveTTL = %v, want 5m (strictest)", got.EffectiveTTL)
	}
}

// TestEvaluate_ScopeCombos covers block_scope_combos including trailing-"*"
// wildcard matching and the "only part of the combo present" allow case.
func TestEvaluate_ScopeCombos(t *testing.T) {
	t.Parallel()
	combo := [][]string{{"admin:*", "openid"}}
	cases := []struct {
		name     string
		scopes   []string
		wantDeny bool
	}{
		{"full combo with wildcard denies", []string{"admin:read", "openid"}, true},
		{"admin write also matches wildcard", []string{"admin:write", "openid", "profile"}, true},
		{"admin without openid allowed", []string{"admin:read", "profile"}, false},
		{"openid without admin allowed", []string{"openid", "profile"}, false},
		{"empty scopes allowed", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Evaluate(PolicyInput{
				ClientID: "c", Scopes: tc.scopes, Kind: KindAccess,
				RequestedTTL: time.Hour,
			}, []Policy{{Name: "p", BlockScopeCombos: combo}})
			if got.Deny != tc.wantDeny {
				t.Fatalf("Deny = %v, want %v (%+v)", got.Deny, tc.wantDeny, got)
			}
			if tc.wantDeny && got.Reason != DenyScopeCombo {
				t.Fatalf("Reason = %q, want %q", got.Reason, DenyScopeCombo)
			}
			// A deny must NOT corrupt the (still downward-only) TTL.
			if got.EffectiveTTL != time.Hour {
				t.Fatalf("EffectiveTTL = %v, want unchanged 1h", got.EffectiveTTL)
			}
		})
	}
}

// TestEvaluate_RefreshDepth proves max_refresh_depth fires only for KindRefresh
// and only at/over the cap.
func TestEvaluate_RefreshDepth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		kind     Kind
		depth    int
		cap      int
		wantDeny bool
	}{
		{"at cap on refresh denies", KindRefresh, 3, 3, true},
		{"over cap on refresh denies", KindRefresh, 4, 3, true},
		{"below cap allowed", KindRefresh, 2, 3, false},
		{"access kind never trips", KindAccess, 9, 3, false},
		{"unset cap never trips", KindRefresh, 9, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Evaluate(PolicyInput{
				ClientID: "c", Kind: tc.kind, RefreshDepth: tc.depth,
			}, []Policy{{Name: "p", MaxRefreshDepth: tc.cap}})
			if got.Deny != tc.wantDeny {
				t.Fatalf("Deny = %v, want %v", got.Deny, tc.wantDeny)
			}
			if tc.wantDeny && got.Reason != DenyRefreshDepth {
				t.Fatalf("Reason = %q, want %q", got.Reason, DenyRefreshDepth)
			}
		})
	}
}

// TestEvaluate_ActiveSessions proves max_active_sessions denies at/over the cap.
func TestEvaluate_ActiveSessions(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		active   int
		cap      int
		wantDeny bool
	}{
		{"at cap denies", 2, 2, true},
		{"over cap denies", 5, 2, true},
		{"below cap allowed", 1, 2, false},
		{"unset cap never trips", 99, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := Evaluate(PolicyInput{
				ClientID: "c", Kind: KindAccess, ActiveSessions: tc.active,
			}, []Policy{{Name: "p", MaxActiveSessions: tc.cap}})
			if got.Deny != tc.wantDeny {
				t.Fatalf("Deny = %v, want %v", got.Deny, tc.wantDeny)
			}
			if tc.wantDeny && got.Reason != DenyActiveSessions {
				t.Fatalf("Reason = %q, want %q", got.Reason, DenyActiveSessions)
			}
		})
	}
}

// TestEvaluate_RequireRenew surfaces the strictest (smallest positive)
// require_renew fraction across matching policies.
func TestEvaluate_RequireRenew(t *testing.T) {
	t.Parallel()
	got := Evaluate(PolicyInput{ClientID: "c", Kind: KindAccess}, []Policy{
		{Name: "loose", RequireRenewAfter: 0.8},
		{Name: "tight", RequireRenewAfter: 0.5},
	})
	if got.RenewAfter != 0.5 {
		t.Fatalf("RenewAfter = %v, want 0.5 (strictest)", got.RenewAfter)
	}
	none := Evaluate(PolicyInput{ClientID: "c"}, []Policy{{Name: "p"}})
	if none.RenewAfter != 0 {
		t.Fatalf("RenewAfter = %v, want 0 when unset", none.RenewAfter)
	}
}

// TestEvaluate_SelectorMatching proves a rule applies only when its ClientID +
// scope selector matches; a non-matching rule contributes nothing.
func TestEvaluate_SelectorMatching(t *testing.T) {
	t.Parallel()
	// Client-scoped rule: applies to c1, not c2.
	clientRule := []Policy{{Name: "c1-only", ClientID: "c1", MaxTTL: 5 * time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c1", RequestedTTL: time.Hour}, clientRule); got.EffectiveTTL != 5*time.Minute {
		t.Fatalf("c1 EffectiveTTL = %v, want 5m", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c2", RequestedTTL: time.Hour}, clientRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("c2 EffectiveTTL = %v, want unchanged 1h", got.EffectiveTTL)
	}

	// Scope-scoped rule: applies only when ALL selector scopes are present.
	scopeRule := []Policy{{Name: "hi-value", Scopes: []string{"payments"}, MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", Scopes: []string{"payments", "openid"}, RequestedTTL: time.Hour}, scopeRule); got.EffectiveTTL != time.Minute {
		t.Fatalf("matching-scope EffectiveTTL = %v, want 1m", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c", Scopes: []string{"openid"}, RequestedTTL: time.Hour}, scopeRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("non-matching-scope EffectiveTTL = %v, want unchanged 1h", got.EffectiveTTL)
	}
}

// TestEvaluate_DenyReasonDeterministic proves that when one policy trips
// multiple dimensions the FIRST in dimension order (scope combo) wins, so the
// reason is stable.
func TestEvaluate_DenyReasonDeterministic(t *testing.T) {
	t.Parallel()
	got := Evaluate(PolicyInput{
		ClientID: "c", Kind: KindAccess,
		Scopes: []string{"admin:x", "openid"}, ActiveSessions: 99,
	}, []Policy{{
		Name:              "p",
		BlockScopeCombos:  [][]string{{"admin:*", "openid"}},
		MaxActiveSessions: 1,
	}})
	if !got.Deny || got.Reason != DenyScopeCombo {
		t.Fatalf("Reason = %q (deny=%v), want %q first", got.Reason, got.Deny, DenyScopeCombo)
	}
}

// TestEvaluate_NoPoliciesIsAllowWithRequestedTTL is the byte-identical default:
// an empty policy set never denies and never changes the TTL.
func TestEvaluate_NoPoliciesIsAllowWithRequestedTTL(t *testing.T) {
	t.Parallel()
	got := Evaluate(PolicyInput{ClientID: "c", RequestedTTL: 42 * time.Minute, Kind: KindAccess}, nil)
	if got.Deny || got.EffectiveTTL != 42*time.Minute || got.RenewAfter != 0 {
		t.Fatalf("empty-policy decision = %+v, want allow/42m/0", got)
	}
}

// TestRenewExceeded is the pure require_renew boundary truth table: a token past
// its renew fraction of TTL exceeds; an unmeasurable one (unset fraction / zero
// timestamps / non-positive TTL) NEVER does (fail-safe — a token whose renewal
// window can't be measured is never spuriously reported inactive).
func TestRenewExceeded(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	// TTL 60s. issued40 → 40s elapsed (0.666 fraction); issued30 → 30s (0.5).
	issued40 := now.Add(-40 * time.Second)
	issued30 := now.Add(-30 * time.Second)
	expires := now.Add(20 * time.Second)
	expires30 := now.Add(30 * time.Second)
	cases := []struct {
		name            string
		renewAfter      float64
		issued, expires time.Time
		want            bool
	}{
		{"unset fraction never exceeds", 0, issued40, expires, false},
		{"past 0.5 threshold", 0.5, issued40, expires, true},
		{"below 0.8 threshold", 0.8, issued40, expires, false},
		{"boundary elapsed==threshold is inclusive", 0.5, issued30, expires30, true},
		{"zero issued time fails safe", 0.5, time.Time{}, expires, false},
		{"zero expiry time fails safe", 0.5, issued40, time.Time{}, false},
		{"non-positive TTL fails safe", 0.5, now, now.Add(-time.Second), false},
		{"negative fraction fails safe", -0.1, issued40, expires, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RenewExceeded(tc.renewAfter, tc.issued, tc.expires, now); got != tc.want {
				t.Fatalf("RenewExceeded(%v) = %v, want %v", tc.renewAfter, got, tc.want)
			}
		})
	}
}

// TestRenewAt_MatchesRenewExceededThreshold proves RenewAt returns exactly
// the boundary RenewExceeded starts firing at, for the same inputs, and
// fails safe (zero time) under the identical unmeasurable conditions.
func TestRenewAt_MatchesRenewExceededThreshold(t *testing.T) {
	t.Parallel()
	issued := time.Unix(1_700_000_000, 0)
	expires := issued.Add(60 * time.Second)

	cases := []struct {
		name       string
		renewAfter float64
		issued     time.Time
		expires    time.Time
		want       time.Time
	}{
		{"unset fraction fails safe", 0, issued, expires, time.Time{}},
		{"0.5 fraction of 60s TTL", 0.5, issued, expires, issued.Add(30 * time.Second)},
		{"0.8 fraction of 60s TTL", 0.8, issued, expires, issued.Add(48 * time.Second)},
		{"zero issued time fails safe", 0.5, time.Time{}, expires, time.Time{}},
		{"zero expiry time fails safe", 0.5, issued, time.Time{}, time.Time{}},
		{"non-positive TTL fails safe", 0.5, issued, issued.Add(-time.Second), time.Time{}},
		{"negative fraction fails safe", -0.1, issued, expires, time.Time{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RenewAt(tc.renewAfter, tc.issued, tc.expires)
			if !got.Equal(tc.want) {
				t.Fatalf("RenewAt(%v) = %v, want %v", tc.renewAfter, got, tc.want)
			}
			// Cross-check against RenewExceeded: just before the returned
			// time it must not be exceeded; at or after it, it must be.
			if !tc.want.IsZero() {
				if RenewExceeded(tc.renewAfter, tc.issued, tc.expires, got.Add(-time.Second)) {
					t.Error("RenewExceeded fired before RenewAt's returned threshold")
				}
				if !RenewExceeded(tc.renewAfter, tc.issued, tc.expires, got) {
					t.Error("RenewExceeded did not fire AT RenewAt's returned threshold")
				}
			}
		})
	}
}
