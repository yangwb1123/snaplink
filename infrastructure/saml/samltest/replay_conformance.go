// Package samltest hosts shared conformance suites for the SAML store SPIs that
// have both an in-memory default and a sqlite peer (the SP/IdP replay-dedup
// stores + the IdP session index). Each backend's test file calls the matching
// suite with its OWN factory, so memory and sqlite are locked to identical
// observable behavior — the dedup-semantics and index-CRUD operators rely on
// can't drift between backends (mirrors permissions/permissionstest).
//
// It lives in a separate package so the production sp/idp packages stay free of
// the `testing` import, and so both the memory side (sp/idp internal tests) and
// the sqlite side (sp/sqlite, idp/sqlite tests) can import ONE suite.
package samltest

import (
	"testing"
	"time"
)

// ReplayChecker is the common shape of every SAML replay store
// (sp.ReplayStore / idp.LogoutReplayStore): CheckAndRemember(id, expires, now)
// reports true when id is FRESH (first sighting in its window) and false when it
// is a REPLAY. Both interfaces have this exact method, so one suite covers both.
type ReplayChecker interface {
	CheckAndRemember(id string, expires, now time.Time) bool
}

// ReplayConformance exercises every replay-dedup semantic both backends MUST
// agree on. Factory returns a FRESH, EMPTY store per subtest (state leakage
// across subtests would mask a backend bug). A non-nil Cleanup is called after
// each subtest (e.g. to Close a sqlite store).
type ReplayConformance struct {
	Factory func(t *testing.T) ReplayChecker
}

// Run executes every replay conformance subtest against the suite's Factory.
func (s ReplayConformance) Run(t *testing.T) {
	t.Helper()
	if s.Factory == nil {
		t.Fatal("ReplayConformance: Factory required")
	}
	// NOTE: a BLANK id is deliberately NOT a conformance case. Every caller
	// guards id != "" before reaching the store (validator.go / slo.go /
	// handlers.go), so blank input never occurs in production and the two
	// backends are free to handle it differently (the sqlite peer short-circuits
	// blank → fresh defensively; the memory store records it). Asserting parity on
	// an input no caller sends would force a no-op change to the byte-identical
	// memory default — out of scope.
	cases := []struct {
		name string
		fn   func(*testing.T, ReplayChecker)
	}{
		{"FirstSeenThenReplay", testFirstSeenThenReplay},
		{"DistinctIDsBothFresh", testDistinctIDsBothFresh},
		{"WithinWindowIsReplay", testWithinWindowIsReplay},
		{"ExpiredPrunedThenFreshAgain", testExpiredPrunedThenFreshAgain},
		{"FutureNowAfterExpiryFresh", testFutureNowAfterExpiryFresh},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			store := s.Factory(t)
			c.fn(t, store)
		})
	}
}

func testFirstSeenThenReplay(t *testing.T, s ReplayChecker) {
	now := time.Now()
	exp := now.Add(time.Hour)
	if !s.CheckAndRemember("id-1", exp, now) {
		t.Fatal("first sighting of id-1 reported as replay")
	}
	if s.CheckAndRemember("id-1", exp, now) {
		t.Fatal("second sighting of id-1 NOT reported as replay")
	}
}

func testDistinctIDsBothFresh(t *testing.T, s ReplayChecker) {
	now := time.Now()
	exp := now.Add(time.Hour)
	if !s.CheckAndRemember("id-a", exp, now) {
		t.Fatal("id-a first sighting reported as replay")
	}
	if !s.CheckAndRemember("id-b", exp, now) {
		t.Fatal("id-b (distinct) first sighting reported as replay")
	}
	// And each is now a replay.
	if s.CheckAndRemember("id-a", exp, now) || s.CheckAndRemember("id-b", exp, now) {
		t.Fatal("a recorded id read as fresh on re-presentation")
	}
}

func testWithinWindowIsReplay(t *testing.T, s ReplayChecker) {
	t0 := time.Now()
	exp := t0.Add(10 * time.Second)
	if !s.CheckAndRemember("id-1", exp, t0) {
		t.Fatal("first sighting reported as replay")
	}
	// Re-presented 5s later, still inside the window ⇒ replay.
	if s.CheckAndRemember("id-1", exp, t0.Add(5*time.Second)) {
		t.Fatal("within-window re-presentation NOT detected as replay")
	}
}

func testExpiredPrunedThenFreshAgain(t *testing.T, s ReplayChecker) {
	t0 := time.Now()
	exp := t0.Add(10 * time.Second)
	if !s.CheckAndRemember("id-1", exp, t0) {
		t.Fatal("first sighting reported as replay")
	}
	if s.CheckAndRemember("id-1", exp, t0.Add(5*time.Second)) {
		t.Fatal("within-window re-presentation NOT a replay")
	}
	// After the window lapses, the prune drops the entry so the SAME id reads
	// fresh again (by then the caller's own expiry check rejects it). Both
	// backends must agree on this — it proves neither leaks entries forever.
	if !s.CheckAndRemember("id-1", exp, t0.Add(20*time.Second)) {
		t.Fatal("post-expiry presentation should read fresh after prune")
	}
}

func testFutureNowAfterExpiryFresh(t *testing.T, s ReplayChecker) {
	t0 := time.Now()
	// expires exactly at t0+10s; presenting AT the boundary (now == expires) must
	// prune (expires <= now), so it reads fresh. Locks the boundary condition
	// (the memory store uses `!expires.After(now)`; sqlite uses `expires_at<=?`).
	exp := t0.Add(10 * time.Second)
	if !s.CheckAndRemember("id-1", exp, t0) {
		t.Fatal("first sighting reported as replay")
	}
	if !s.CheckAndRemember("id-1", exp, exp) {
		t.Fatal("presentation exactly at expiry should prune+read fresh")
	}
}
