package middleware

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

// realClientIPKey is the unexported context key for the validated client IP.
// Unexported to prevent collisions with other packages.
type realClientIPKey struct{}

// forwardedTrustKey is the unexported context key for the peer-trust verdict:
// whether the request's DIRECT TCP peer is inside the trusted-proxy CIDRs and
// its proxy-supplied headers (X-Forwarded-*) may therefore be honored.
type forwardedTrustKey struct{}

// TrustedProxies validates X-Forwarded-For against a CIDR allowlist,
// deriving the "real" client IP by walking the XFF chain from right to
// left and stopping at the first hop that is NOT in a trusted CIDR. This
// prevents a forged XFF header from appearing to come from a trusted proxy.
//
// The chain walk only runs when the DIRECT peer (r.RemoteAddr) is itself
// inside a trusted CIDR — a request that reached us without transiting a
// trusted proxy carries an XFF the peer forged wholesale, so the middleware
// falls back to RemoteAddr and marks every forwarded header untrusted for
// downstream consumers (BaseURL, mesh identity — see ForwardedHeadersTrusted).
//
// When not installed, RealClientIP falls back to r.RemoteAddr —
// so callers that use RealClientIP are byte-identical to today's behaviour
// when no TrustedProxies middleware is in the chain.
type TrustedProxies struct {
	checker *peertrust.Checker
	hops    int
}

// NewTrustedProxies builds a TrustedProxies from a list of CIDR strings.
// hops controls how many trusted proxy tiers to peel off the right end of
// the X-Forwarded-For list before accepting the first untrusted IP as the
// real client. hops=0 means "peel at most len(cidrs) tiers" — a safe
// default for most deployments where each CIDR represents one proxy tier.
//
// Returns an error if any CIDR fails to parse, so misconfigured deployments
// fail loudly at startup rather than silently trusting the raw header.
func NewTrustedProxies(cidrs []string, hops int) (*TrustedProxies, error) {
	checker, err := peertrust.NewChecker(cidrs)
	if err != nil {
		return nil, err
	}
	if hops <= 0 {
		hops = len(cidrs)
	}
	return &TrustedProxies{checker: checker, hops: hops}, nil
}

// resolve derives the validated client IP for r. When the direct peer is
// untrusted the XFF header is attacker-supplied wholesale and is ignored;
// otherwise the X-Forwarded-For hops are walked right-to-left, skipping
// IPs that belong to trusted proxy CIDRs. The first IP that is either
// untrusted or immediately to the left of the last trusted hop (when the
// hops budget is exhausted) is returned as the real client IP.
//
// The hops budget prevents an operator misconfiguration (or an
// attacker with control of upstream trusted nodes) from peeling more
// proxy tiers than the deployment has: once the budget is consumed the
// walk stops and the entry to the left of the last trusted hop is
// returned, even if it is also in a trusted CIDR.
func (tp *TrustedProxies) resolve(r *http.Request) string {
	if !tp.checker.TrustsRemoteAddr(r.RemoteAddr) {
		return stripPort(r.RemoteAddr)
	}
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return stripPort(r.RemoteAddr)
	}

	// Split into individual hops; rightmost is nearest to the server.
	parts := strings.Split(xff, ",")
	return tp.walkChain(parts)
}

// walkChain walks the X-Forwarded-For hops in parts right-to-left and
// returns the resolved real client IP. For each hop:
//   - If it is trusted and the hops budget allows, skip it.
//   - If it is untrusted, it is the real client — return it.
//   - If the hop is unparseable, stop here (malformed input) and
//     treat the entry one position to the right as the boundary.
//
// After the loop we know the first i where we stopped; the entry
// at parts[i] (or parts[0] when we exhausted the whole list) is
// the real client.
//
// Exhausting the whole list without finding an untrusted hop (all
// IPs are in trusted CIDRs) returns the leftmost entry, the closest
// approximation to the original client.
func (tp *TrustedProxies) walkChain(parts []string) string {
	hops := tp.hops
	for i := len(parts) - 1; i >= 0; i-- {
		raw := strings.TrimSpace(parts[i])
		ip, ok := parseHop(raw)
		if !ok {
			// Unparseable hop — stop; the entry to our left is the client.
			if i > 0 {
				return strings.TrimSpace(parts[i-1])
			}
			return raw
		}
		if tp.checker.TrustsAddr(ip) {
			if hops <= 0 {
				// Budget exhausted — this trusted hop is as far right as
				// we were allowed to look. The entry to our left is the
				// real client (may itself be trusted, but we cannot peel
				// further without exceeding the operator's declared depth).
				if i > 0 {
					return strings.TrimSpace(parts[i-1])
				}
				return raw
			}
			hops--
			// Continue walking left.
			continue
		}
		// First untrusted hop encountered — this is the real client.
		return raw
	}
	return strings.TrimSpace(parts[0])
}

// parseHop parses one XFF chain entry. Zoned IPv6 literals are rejected to
// preserve the pre-netip (net.ParseIP) walk semantics: a zoned hop counts
// as malformed input, not as an untrusted client address.
func parseHop(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return ip, true
}

// Middleware wraps next, validates the X-Forwarded-For chain against the
// trusted CIDR list, and stores the validated real client IP plus the
// peer-trust verdict in the request context so downstream consumers can
// retrieve them via RealClientIP / ForwardedHeadersTrusted.
//
// When tp is nil the middleware is a no-op pass-through — callers can
// always wrap unconditionally without a nil-guard.
func (tp *TrustedProxies) Middleware(next http.Handler) http.Handler {
	if tp == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := tp.resolve(r)
		ctx := context.WithValue(r.Context(), realClientIPKey{}, ip)
		ctx = context.WithValue(ctx, forwardedTrustKey{},
			tp.checker.TrustsRemoteAddr(r.RemoteAddr))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RealClientIP returns the validated client IP stored by TrustedProxies
// middleware. When no TrustedProxies middleware is in the chain — either
// because none was configured or because the request bypasses it — it
// falls back to r.RemoteAddr (port stripped), so callers are
// byte-identical to pre-TrustedProxies behaviour when the middleware is
// absent.
func RealClientIP(r *http.Request) string {
	if v, ok := r.Context().Value(realClientIPKey{}).(string); ok && v != "" {
		return v
	}
	return stripPort(r.RemoteAddr)
}

// ForwardedHeadersTrusted reports whether proxy-supplied headers
// (X-Forwarded-Proto/Host and friends) on this request may be honored.
// TrustedProxies middleware stamps false when the DIRECT peer is outside
// the trusted CIDRs — the headers were then forged wholesale by the peer.
// With no verdict in the context (no TrustedProxies configured, or the
// request bypassed the chain) it returns true, preserving the legacy
// first-hop-trust behavior byte-identically.
func ForwardedHeadersTrusted(r *http.Request) bool {
	if r == nil {
		return true
	}
	if v, ok := r.Context().Value(forwardedTrustKey{}).(bool); ok {
		return v
	}
	return true
}

// stripPort removes the :<port> suffix from a host:port address, returning
// just the host. IPv6 literals ([::1]:port) are handled correctly.
func stripPort(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
