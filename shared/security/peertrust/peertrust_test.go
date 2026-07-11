package peertrust

import (
	"net/netip"
	"testing"
)

func TestNewChecker_EmptyIsUnconfigured(t *testing.T) {
	t.Parallel()
	c, err := NewChecker(nil)
	if err != nil {
		t.Fatalf("NewChecker(nil): %v", err)
	}
	if c != nil {
		t.Fatalf("NewChecker(nil) = %v, want nil (unconfigured sentinel)", c)
	}
	// The nil sentinel trusts nobody — consumers must nil-guard to keep
	// legacy behavior, never rely on a nil checker saying "trusted".
	if c.TrustsRemoteAddr("10.0.0.1:80") {
		t.Error("nil checker trusted a peer")
	}
}

func TestNewChecker_BadCIDRFailsLoud(t *testing.T) {
	t.Parallel()
	if _, err := NewChecker([]string{"10.0.0.0/8", "not-a-cidr"}); err == nil {
		t.Fatal("expected parse error for invalid CIDR, got nil")
	}
}

func TestChecker_TrustsRemoteAddr(t *testing.T) {
	t.Parallel()
	c, err := NewChecker([]string{"10.0.0.0/8", "2001:db8::/32", "192.168.1.1/24"})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	cases := []struct {
		addr string
		want bool
	}{
		{"10.1.2.3:443", true},
		{"10.1.2.3", true}, // bare host, no port
		{"[2001:db8::1]:8443", true},
		{"[::ffff:10.0.0.9]:80", true}, // IPv4-mapped peer on a dual-stack listener
		{"192.168.1.200:1", true},      // host bits masked: /24 covers the whole net
		{"203.0.113.5:443", false},
		{"[2001:db9::1]:443", false},
		{"garbage:443", false}, // unparseable → untrusted (fail toward not honoring)
		{"", false},
	}
	for _, tc := range cases {
		if got := c.TrustsRemoteAddr(tc.addr); got != tc.want {
			t.Errorf("TrustsRemoteAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestChecker_TrustsAddr_UnmapsIPv4In6(t *testing.T) {
	t.Parallel()
	c, err := NewChecker([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	mapped := netip.MustParseAddr("::ffff:10.0.0.1")
	if !c.TrustsAddr(mapped) {
		t.Error("IPv4-mapped IPv6 addr did not match its IPv4 CIDR")
	}
}
