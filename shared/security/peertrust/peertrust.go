// Package peertrust compiles the operator's trusted-proxy CIDR list into an
// immutable peer-trust Checker consulted wherever a proxy-supplied request
// input (X-Forwarded-*, forwarded client-cert header, serving-region header,
// mesh identity derivation) would otherwise be honored unconditionally.
//
// It lives at the shared kernel layer so every consumer — interfaces
// middleware (base URL, XFF chain), domains/region (serving-region header),
// and securityverify (mTLS header backend) — can take a *Checker as an
// optional seam without violating the one-way layer import direction.
// A nil *Checker means "no trust gate configured": every consumer treats it
// as absent and keeps its pre-gate behavior byte-identical.
package peertrust

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// Checker answers "is this direct TCP peer one of my trusted proxies?".
// It is compiled once at startup from the operator's CIDR list and is
// immutable (and therefore safe for concurrent use) afterwards.
type Checker struct {
	prefixes []netip.Prefix
}

// NewChecker compiles cidrs into a Checker. An empty list returns
// (nil, nil) — the "unconfigured" sentinel consumers use to keep legacy
// behavior. Any unparseable entry errors so a misconfigured deployment
// fails loudly at startup instead of silently trusting (or distrusting)
// the wrong peers.
func NewChecker(cidrs []string) (*Checker, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("peertrust: cidr %q: %w", c, err)
		}
		// Masked so a host-bit-carrying entry ("10.0.0.1/8") matches the
		// whole network, mirroring net.ParseCIDR semantics.
		prefixes = append(prefixes, p.Masked())
	}
	return &Checker{prefixes: prefixes}, nil
}

// TrustsAddr reports whether a falls inside any trusted CIDR. IPv4-mapped
// IPv6 addresses (::ffff:10.0.0.1) are unmapped first so a dual-stack
// listener's peers match their IPv4 CIDRs — the same containment semantics
// net.IPNet.Contains has. Nil-safe: an unconfigured Checker trusts nobody.
func (c *Checker) TrustsAddr(a netip.Addr) bool {
	if c == nil {
		return false
	}
	a = a.Unmap()
	for _, p := range c.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// TrustsRemoteAddr reports whether the direct peer behind an
// http.Request.RemoteAddr-shaped "host:port" (or bare host) string is
// trusted. Unparseable input is untrusted — fail toward NOT honoring
// proxy-supplied headers.
func (c *Checker) TrustsRemoteAddr(remoteAddr string) bool {
	if c == nil || remoteAddr == "" {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return c.TrustsAddr(a)
}
