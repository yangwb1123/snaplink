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

// TestEvaluate_TenantSelector proves the tenant dimension: a rule matches only
// its own tenant, an empty policy tenant is a GLOBAL rule for every tenant,
// and a zero input tenant (single-tenant deployment) never matches a
// tenant-scoped rule — the byte-compat contract.
func TestEvaluate_TenantSelector(t *testing.T) {
	t.Parallel()
	tenantRule := []Policy{{Name: "ta-cap", TenantID: "ta", MaxTTL: 5 * time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", TenantID: "ta", RequestedTTL: time.Hour}, tenantRule); got.EffectiveTTL != 5*time.Minute {
		t.Fatalf("ta EffectiveTTL = %v, want 5m", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c", TenantID: "tb", RequestedTTL: time.Hour}, tenantRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("tb EffectiveTTL = %v, want unchanged 1h (other tenant)", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c", TenantID: "", RequestedTTL: time.Hour}, tenantRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("zero-tenant EffectiveTTL = %v, want unchanged 1h (single-tenant byte-compat)", got.EffectiveTTL)
	}
	// Empty policy tenant = global: applies to any input tenant.
	globalRule := []Policy{{Name: "global", MaxTTL: time.Minute}}
	for _, tenant := range []string{"", "ta", "tb"} {
		if got := Evaluate(PolicyInput{ClientID: "c", TenantID: tenant, RequestedTTL: time.Hour}, globalRule); got.EffectiveTTL != time.Minute {
			t.Fatalf("global rule for tenant %q EffectiveTTL = %v, want 1m", tenant, got.EffectiveTTL)
		}
	}
}

// TestEvaluate_TenantRuleTightensOnly proves the load-bearing no-widening
// invariant BOTH directions: tenant 5m + global 10m => 5m (tenant tightens),
// and the reverse combination tenant 10m + global 5m => 5m (a tenant rule can
// never raise a global ceiling — the strictest-wins union is unchanged).
func TestEvaluate_TenantRuleTightensOnly(t *testing.T) {
	t.Parallel()
	both := []Policy{
		{Name: "tenant", TenantID: "ta", MaxTTL: 5 * time.Minute},
		{Name: "global", MaxTTL: 10 * time.Minute},
	}
	if got := Evaluate(PolicyInput{ClientID: "c", TenantID: "ta", RequestedTTL: time.Hour}, both); got.EffectiveTTL != 5*time.Minute {
		t.Fatalf("tenant-tightens EffectiveTTL = %v, want 5m", got.EffectiveTTL)
	}
	reverse := []Policy{
		{Name: "tenant", TenantID: "ta", MaxTTL: 10 * time.Minute},
		{Name: "global", MaxTTL: 5 * time.Minute},
	}
	if got := Evaluate(PolicyInput{ClientID: "c", TenantID: "ta", RequestedTTL: time.Hour}, reverse); got.EffectiveTTL != 5*time.Minute {
		t.Fatalf("reverse EffectiveTTL = %v, want 5m (tenant rule must never widen)", got.EffectiveTTL)
	}
}

// TestEvaluate_ClientPrefixWildcard proves the client selector accepts the
// same trailing-"*" prefix wildcard as scopes: "payments-*" matches
// "payments-api" but not "billing", and an exact rule stays exact.
func TestEvaluate_ClientPrefixWildcard(t *testing.T) {
	t.Parallel()
	rule := []Policy{{Name: "pay", ClientID: "payments-*", MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "payments-api", RequestedTTL: time.Hour}, rule); got.EffectiveTTL != time.Minute {
		t.Fatalf("payments-api EffectiveTTL = %v, want 1m", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "billing", RequestedTTL: time.Hour}, rule); got.EffectiveTTL != time.Hour {
		t.Fatalf("billing EffectiveTTL = %v, want unchanged 1h", got.EffectiveTTL)
	}
}

// TestEvaluate_SubjectSelector proves the subject dimension: "svc-*" matches
// svc-payments but not a human subject, exact match works, and an absent
// input subject never matches (the documented inertness of subject rules at
// seams that resolve no subject — fail-open).
func TestEvaluate_SubjectSelector(t *testing.T) {
	t.Parallel()
	subjectRule := []Policy{{Name: "svc", Subject: "svc-*", MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", Subject: "svc-payments", RequestedTTL: time.Hour}, subjectRule); got.EffectiveTTL != time.Minute {
		t.Fatalf("svc-payments EffectiveTTL = %v, want 1m", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c", Subject: "alice", RequestedTTL: time.Hour}, subjectRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("alice EffectiveTTL = %v, want unchanged 1h", got.EffectiveTTL)
	}
	exactRule := []Policy{{Name: "alice", Subject: "alice", MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", Subject: "alice", RequestedTTL: time.Hour}, exactRule); got.EffectiveTTL != time.Minute {
		t.Fatalf("exact-subject EffectiveTTL = %v, want 1m", got.EffectiveTTL)
	}
}

// TestEvaluate_SubjectSelector_NoMatchWhenSubjectAbsent pins the clamp-seam
// inertness (security F2 / QA H2): the ClampingIssuer supplies no Subject, so
// a subject-scoped max_ttl rule never clamps — the seam sees no subject, the
// rule is a documented no-op, and the TTL stays unchanged.
func TestEvaluate_SubjectSelector_NoMatchWhenSubjectAbsent(t *testing.T) {
	t.Parallel()
	got := Evaluate(PolicyInput{ClientID: "c", TenantID: "ta", RequestedTTL: time.Hour},
		[]Policy{{Subject: "svc-*", MaxTTL: 5 * time.Minute}})
	if got.EffectiveTTL != time.Hour {
		t.Fatalf("EffectiveTTL = %v, want unchanged 1h (subject selector inert without input subject)", got.EffectiveTTL)
	}
}

// TestEvaluate_SubjectRolesSelector proves the role dimension: the input's
// roles intersect the selector (any one entry suffices), a disjoint set never
// matches, and EMPTY input roles intersect nothing — the fail-open contract
// that makes role selectors inert during a roster outage / on unwired
// deployments.
func TestEvaluate_SubjectRolesSelector(t *testing.T) {
	t.Parallel()
	roleRule := []Policy{{Name: "admin", SubjectRoles: []string{"admin"}, MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", SubjectRoles: []string{"member", "admin"}, RequestedTTL: time.Hour}, roleRule); got.EffectiveTTL != time.Minute {
		t.Fatalf("admin-holder EffectiveTTL = %v, want 1m", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c", SubjectRoles: []string{"member"}, RequestedTTL: time.Hour}, roleRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("member-only EffectiveTTL = %v, want unchanged 1h", got.EffectiveTTL)
	}
	if got := Evaluate(PolicyInput{ClientID: "c", RequestedTTL: time.Hour}, roleRule); got.EffectiveTTL != time.Hour {
		t.Fatalf("empty-roles EffectiveTTL = %v, want unchanged 1h (fail-open: role selectors inert)", got.EffectiveTTL)
	}
	multiRule := []Policy{{Name: "priv", SubjectRoles: []string{"guest", "admin"}, MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", SubjectRoles: []string{"admin"}, RequestedTTL: time.Hour}, multiRule); got.EffectiveTTL != time.Minute {
		t.Fatalf("multi-role intersection EffectiveTTL = %v, want 1m", got.EffectiveTTL)
	}
}

// TestEvaluate_AllEmptySelectorsByteIdentical proves a rule with every new
// selector empty behaves exactly like the pre-feature engine for any input —
// the legacy byte-compat regression pin.
func TestEvaluate_AllEmptySelectorsByteIdentical(t *testing.T) {
	t.Parallel()
	rule := []Policy{{Name: "global", MaxTTL: time.Minute}}
	for _, in := range []PolicyInput{
		{ClientID: "c", RequestedTTL: time.Hour},
		{ClientID: "c", TenantID: "ta", Subject: "alice", SubjectRoles: []string{"admin"}, RequestedTTL: time.Hour},
	} {
		if got := Evaluate(in, rule); got.EffectiveTTL != time.Minute {
			t.Fatalf("input %+v EffectiveTTL = %v, want 1m (selectors empty => old behavior)", in, got.EffectiveTTL)
		}
	}
}

// TestEvaluate_LegacyBareStarScopeStillMatchAll proves the legacy scope
// selector keeps its match-all semantics: a bare "*" scope rule matches every
// request exactly as before the strictness work (Validate gates only the NEW
// selectors; scopePresent semantics are unchanged).
func TestEvaluate_LegacyBareStarScopeStillMatchAll(t *testing.T) {
	t.Parallel()
	rule := []Policy{{Name: "legacy", Scopes: []string{"*"}, MaxTTL: time.Minute}}
	if got := Evaluate(PolicyInput{ClientID: "c", Scopes: []string{"anything"}, RequestedTTL: time.Hour}, rule); got.EffectiveTTL != time.Minute {
		t.Fatalf("bare-star scope EffectiveTTL = %v, want 1m (match-all preserved)", got.EffectiveTTL)
	}
}

// TestEvaluate_IntrospectionShapeTenantInert pins the fifth evaluation site's
// documented inertness (security F2): IntrospectionRenewExceeded supplies
// only ClientID + Scopes (Decision 5 keeps tenant out of claims), so a
// tenant-scoped require_renew_after rule never fires there — RenewAfter stays
// zero and the token is never force-renewed by it.
func TestEvaluate_IntrospectionShapeTenantInert(t *testing.T) {
	t.Parallel()
	got := Evaluate(PolicyInput{ClientID: "c", Scopes: []string{"openid"}, Kind: KindAccess},
		[]Policy{{TenantID: "ta", RequireRenewAfter: 0.5}})
	if got.RenewAfter != 0 {
		t.Fatalf("RenewAfter = %v, want 0 (tenant rule inert at the introspection shape)", got.RenewAfter)
	}
}

// TestEvaluate_ScopeComboShapeRoleInert pins the scope-combo seam's
// documented inertness: denyTokenScopeCombo supplies client + scopes only
// (no subject, no roles), so a subject_roles-scoped block_scope_combos rule
// never denies there — the combo is a documented no-op, not a widen.
func TestEvaluate_ScopeComboShapeRoleInert(t *testing.T) {
	t.Parallel()
	got := Evaluate(PolicyInput{ClientID: "c", Scopes: []string{"admin:x", "openid"}, Kind: KindAccess},
		[]Policy{{SubjectRoles: []string{"admin"}, BlockScopeCombos: [][]string{{"admin:*", "openid"}}}})
	if got.Deny {
		t.Fatalf("Deny = true, want false (role-scoped combo rule inert without input roles)")
	}
}

// TestPrefixOrExact is the helper's unit truth table: exact match, trailing-"*"
// prefix match, bare "*" (match-all at the engine level — Validate is the
// config gate), empty selector, and non-matching prefix.
func TestPrefixOrExact(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, want string
		match   bool
	}{
		{"payments-api", "payments-api", true},
		{"payments-api", "payments-*", true},
		{"payments-web", "payments-*", true},
		{"billing", "payments-*", false},
		{"anything", "*", true}, // bare "*" matches everything (engine level)
		{"", "", true},          // empty selector = any
		{"alice", "", false},    // empty want matches nothing (matches() guards empty selectors)
		{"alice", "alice", true},
		{"alicia", "alice", false},
	}
	for _, tc := range cases {
		if got := prefixOrExact(tc.a, tc.want); got != tc.match {
			t.Errorf("prefixOrExact(%q, %q) = %v, want %v", tc.a, tc.want, got, tc.match)
		}
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
