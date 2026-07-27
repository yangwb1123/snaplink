package netpolicy

// In-package unit tests for the Classifier's compilation + matching internals
// (compile / normalizeHost / parseIP / Clone / apply / upsert) and the option
// wiring. They live in-package (NOT netpolicy_test) so they can reach the
// unexported helpers + snapshot directly without going through the Store — these
// are pure/index-level behaviors with no backend involved, so no store (and thus
// no import cycle) is needed. Store-driven paths (Reload/Start errors, Watch
// delivery) live in the external classifier_store_test.go alongside the real
// netpolicy/memory backend.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestWithClassifierLoggerWired(t *testing.T) {
	t.Parallel()

	var l spi.Logger = spi.NopLogger{}
	c := NewClassifier(WithClassifierLogger(l))
	if c.logger == nil {
		t.Fatal("WithClassifierLogger did not wire the logger")
	}
	// nil is a documented no-op and must not panic.
	c2 := NewClassifier(WithClassifierLogger(nil))
	if c2.logger != nil {
		t.Fatal("WithClassifierLogger(nil) should leave logger nil")
	}
}

func TestClassifyPriorityTieBreakHostname(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	// Two hostname policies both matching app.example.com; higher priority wins.
	c.upsertLocked(&Policy{Name: "low", Hostnames: []string{"app.example.com"}, Priority: 1})
	c.upsertLocked(&Policy{Name: "high", Hostnames: []string{"app.example.com"}, Priority: 10})

	got := c.Classify("", "app.example.com")
	if got == nil || got.Name != "high" {
		t.Fatalf("priority tie-break = %v, want high", got)
	}
}

func TestClassifyPriorityTieBreakCIDR(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	// Overlapping CIDRs; the higher-priority policy must win even though both
	// contain the IP and the lower one was inserted first.
	c.upsertLocked(&Policy{Name: "broad", CIDRs: []string{"10.0.0.0/8"}, Priority: 1})
	c.upsertLocked(&Policy{Name: "narrow", CIDRs: []string{"10.0.0.0/16"}, Priority: 5})

	got := c.Classify("10.0.0.5", "")
	if got == nil || got.Name != "narrow" {
		t.Fatalf("overlapping-CIDR priority = %v, want narrow", got)
	}
}

func TestClassifyHostnameMissFallsThroughToCIDR(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{Name: "by-host", Hostnames: []string{"other.example.com"}})
	c.upsertLocked(&Policy{Name: "by-cidr", CIDRs: []string{"10.0.0.0/8"}})

	// host doesn't match any hostname policy, but the IP matches a CIDR policy —
	// Pass 1 misses, Pass 2 hits.
	got := c.Classify("10.0.0.1", "nomatch.example.com")
	if got == nil || got.Name != "by-cidr" {
		t.Fatalf("hostname-miss CIDR fallback = %v, want by-cidr", got)
	}
}

func TestClassifyBlankHostAndBadIP(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{Name: "cidr", CIDRs: []string{"10.0.0.0/8"}})

	// Empty host skips Pass 1; an unparseable remoteAddr yields a nil IP so
	// Pass 2 is skipped too — nothing matches.
	if got := c.Classify("not-an-ip", ""); got != nil {
		t.Fatalf("bad IP + blank host = %v, want nil", got)
	}
}

func TestUpsertLockedUpdatesInPlace(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{Name: "p", CIDRs: []string{"10.0.0.0/8"}})
	// Re-upsert same name with a different CIDR: the existing entry is replaced,
	// not duplicated.
	c.upsertLocked(&Policy{Name: "p", CIDRs: []string{"192.168.0.0/16"}})

	sn := c.Snapshot()
	if len(sn) != 1 {
		t.Fatalf("upsert of same name produced %d entries, want 1", len(sn))
	}
	if got := c.Classify("192.168.0.1", ""); got == nil || got.Name != "p" {
		t.Fatalf("updated CIDR not matched: %v", got)
	}
	if got := c.Classify("10.0.0.1", ""); got != nil {
		t.Fatalf("old CIDR still matched after update: %v", got)
	}
}

func TestApplyAddUpdateRemove(t *testing.T) {
	t.Parallel()

	c := NewClassifier()

	c.apply(Event{Type: EventAdded, Policy: &Policy{Name: "p", CIDRs: []string{"10.0.0.0/8"}}})
	if got := c.Classify("10.0.0.1", ""); got == nil || got.Name != "p" {
		t.Fatalf("EventAdded not applied: %v", got)
	}

	c.apply(Event{Type: EventUpdated, Policy: &Policy{Name: "p", CIDRs: []string{"172.16.0.0/12"}}})
	if got := c.Classify("172.16.0.1", ""); got == nil || got.Name != "p" {
		t.Fatalf("EventUpdated not applied: %v", got)
	}

	c.apply(Event{Type: EventRemoved, Policy: &Policy{Name: "p"}})
	if got := c.Classify("172.16.0.1", ""); got != nil {
		t.Fatalf("EventRemoved did not drop policy: %v", got)
	}
	if len(c.Snapshot()) != 0 {
		t.Fatalf("snapshot not empty after remove: %v", c.Snapshot())
	}
}

// TestApplyPanicsOnNilPolicy documents the underlying hazard applySafe exists
// to contain: a custom Store implementation is free to emit a malformed
// Event{Type: EventAdded/EventUpdated, Policy: nil} on its Watch channel (the
// shipped memory + etcd backends never do, but the Store interface doesn't
// forbid it), and apply's dereference of evt.Policy is unconditional. This
// pins that raw apply (used directly by Reload's seed path via replace, and
// historically by run's drain loop) is NOT nil-safe, so the recover in
// applySafe (see TestApplySafeRecoversFromNilPolicyPanic) is load-bearing, not
// redundant.
func TestApplyPanicsOnNilPolicy(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	defer func() {
		if recover() == nil {
			t.Fatal("apply(EventAdded, Policy: nil) did not panic — the recover in applySafe would be dead code")
		}
	}()
	c.apply(Event{Type: EventAdded, Policy: nil})
}

// TestApplySafeRecoversFromNilPolicyPanic proves the fix: the SAME malformed
// event that panics raw apply (see TestApplyPanicsOnNilPolicy) is contained by
// applySafe — the call returns normally instead of taking down the calling
// goroutine (which, on the real run loop, is the detached, permanent-for-the-
// process Watch consumer spawned by Start; an unrecovered panic there crashes
// the entire server, not just this one policy update). The Classifier must
// also stay fully usable afterward: an existing entry keeps classifying and a
// subsequent well-formed event still applies.
func TestApplySafeRecoversFromNilPolicyPanic(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.apply(Event{Type: EventAdded, Policy: &Policy{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}}})

	// Must not panic — a panic here would fail this test AND (per the
	// documented contract) crash the whole process on the real run loop.
	c.applySafe(Event{Type: EventAdded, Policy: nil})
	c.applySafe(Event{Type: EventUpdated, Policy: nil})

	// The classifier survives the malformed events with its prior state intact...
	if got := c.Classify("10.0.0.1", ""); got == nil || got.Name != "intranet" {
		t.Fatalf("classifier state corrupted by recovered panic: %v", got)
	}
	// ...and keeps applying subsequent well-formed events normally.
	c.applySafe(Event{Type: EventAdded, Policy: &Policy{Name: "dmz", CIDRs: []string{"172.16.0.0/12"}}})
	if got := c.Classify("172.16.0.1", ""); got == nil || got.Name != "dmz" {
		t.Fatalf("applySafe did not apply a well-formed event after recovering a panic: %v", got)
	}
}

func TestRemoveLockedUnknownNameNoOp(t *testing.T) {
	t.Parallel()

	c := NewClassifier()
	c.upsertLocked(&Policy{Name: "keep", CIDRs: []string{"10.0.0.0/8"}})
	// Removing a name that isn't present must not touch the existing entry.
	c.removeLocked("ghost")
	if len(c.Snapshot()) != 1 {
		t.Fatalf("removeLocked of unknown name mutated snapshot: %v", c.Snapshot())
	}
}

func TestCompileBareIPUpgrade(t *testing.T) {
	t.Parallel()

	// Bare IPv4 → /32, bare IPv6 → /128. A bare IP should match itself exactly.
	cpv4 := compile(&Policy{Name: "v4", CIDRs: []string{"203.0.113.5"}})
	if len(cpv4.cidrs) != 1 {
		t.Fatalf("bare IPv4 produced %d nets, want 1", len(cpv4.cidrs))
	}
	if !cpv4.cidrs[0].Contains(net.ParseIP("203.0.113.5")) {
		t.Fatal("bare IPv4 /32 does not contain itself")
	}
	if cpv4.cidrs[0].Contains(net.ParseIP("203.0.113.6")) {
		t.Fatal("bare IPv4 should be /32, but matched a neighbor")
	}

	cpv6 := compile(&Policy{Name: "v6", CIDRs: []string{"2001:db8::1"}})
	if len(cpv6.cidrs) != 1 {
		t.Fatalf("bare IPv6 produced %d nets, want 1", len(cpv6.cidrs))
	}
	if !cpv6.cidrs[0].Contains(net.ParseIP("2001:db8::1")) {
		t.Fatal("bare IPv6 /128 does not contain itself")
	}
}

func TestCompileMalformedCIDRDropped(t *testing.T) {
	t.Parallel()

	// A malformed CIDR is silently dropped; the valid one survives so the policy
	// is still addressable.
	cp := compile(&Policy{Name: "mixed", CIDRs: []string{"not-a-cidr", "10.0.0.0/8", "999.999.999.0/24"}})
	if len(cp.cidrs) != 1 {
		t.Fatalf("malformed CIDRs not dropped: got %d nets, want 1", len(cp.cidrs))
	}
	if !cp.cidrs[0].Contains(net.ParseIP("10.0.0.1")) {
		t.Fatal("surviving CIDR does not match expected IP")
	}
}

func TestCompileHostnamesLowercased(t *testing.T) {
	t.Parallel()

	cp := compile(&Policy{Name: "h", Hostnames: []string{"API.Example.COM", "  Mixed.Case  "}})
	if _, ok := cp.hostnames["api.example.com"]; !ok {
		t.Fatalf("hostname not lowercased: %v", cp.hostnames)
	}
	if _, ok := cp.hostnames["mixed.case"]; !ok {
		t.Fatalf("hostname not trimmed+lowercased: %v", cp.hostnames)
	}
}

func TestNormalizeHost(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"Example.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com:8080", "example.com"}, // strip :port
		{"", ""},                            // empty stays empty
		{"[::1]:8080", "[::1]:8080"},        // IPv6 literal w/ port: not stripped (multiple colons)
		{"2001:db8::1", "2001:db8::1"},      // bare IPv6: multiple colons → left intact
	}
	for _, tc := range cases {
		if got := normalizeHost(tc.in); got != tc.want {
			t.Errorf("normalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseIP(t *testing.T) {
	t.Parallel()

	if ip := parseIP("10.0.0.1:443"); ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("parseIP(host:port) = %v, want 10.0.0.1", ip)
	}
	if ip := parseIP("10.0.0.1"); ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("parseIP(bare) = %v, want 10.0.0.1", ip)
	}
	if ip := parseIP("garbage"); ip != nil {
		t.Errorf("parseIP(garbage) = %v, want nil", ip)
	}
	if ip := parseIP(""); ip != nil {
		t.Errorf("parseIP(empty) = %v, want nil", ip)
	}
}

func TestPolicyCloneDeepCopy(t *testing.T) {
	t.Parallel()

	orig := &Policy{
		Name:      "p",
		CIDRs:     []string{"10.0.0.0/8"},
		Hostnames: []string{"a.example.com"},
		Metadata:  map[string]string{"k": "v"},
		Priority:  3,
	}
	cp := orig.Clone()
	// Mutating the clone's slices/map must not touch the original.
	cp.CIDRs[0] = "0.0.0.0/0"
	cp.Hostnames[0] = "evil.example.com"
	cp.Metadata["k"] = "tampered"

	if orig.CIDRs[0] != "10.0.0.0/8" {
		t.Errorf("Clone shares CIDRs slice: %v", orig.CIDRs)
	}
	if orig.Hostnames[0] != "a.example.com" {
		t.Errorf("Clone shares Hostnames slice: %v", orig.Hostnames)
	}
	if orig.Metadata["k"] != "v" {
		t.Errorf("Clone shares Metadata map: %v", orig.Metadata)
	}
}

func TestPolicyCloneNil(t *testing.T) {
	t.Parallel()

	var p *Policy
	if p.Clone() != nil {
		t.Fatal("(*Policy)(nil).Clone() must be nil")
	}
}

func TestReqContext(t *testing.T) {
	t.Parallel()

	// nil request → background context (never nil), defensive against custom
	// transports.
	if reqContext(nil) == nil {
		t.Fatal("reqContext(nil) returned nil")
	}
	// A real request returns its own (non-nil) context.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if reqContext(req) != req.Context() {
		t.Fatal("reqContext(req) did not return req.Context()")
	}
	// A request whose context is explicitly background still yields non-nil.
	if reqContext(req.WithContext(context.Background())) == nil {
		t.Fatal("reqContext(bg) returned nil")
	}
}

func TestPolicyCloneEmptySlicesStayNil(t *testing.T) {
	t.Parallel()

	// A policy with nil slices/map must clone to nil (not empty non-nil) so
	// JSON round-trips identically and omitempty behaves.
	cp := (&Policy{Name: "p"}).Clone()
	if cp.CIDRs != nil || cp.Hostnames != nil || cp.Metadata != nil {
		t.Fatalf("Clone of nil-field policy populated fields: %+v", cp)
	}
}
