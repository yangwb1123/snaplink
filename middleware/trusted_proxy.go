package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// realClientIPKey is the unexported context key for the validated client IP.
// Unexported to prevent collisions with other packages.
type realClientIPKey struct{}

// TrustedProxies validates X-Forwarded-For against a CIDR allowlist,
// deriving the "real" client IP by walking the XFF chain from right to
// left and stopping at the first hop that is NOT in a trusted CIDR. This
// prevents a forged XFF header from appearing to come from a trusted proxy.
//
// When not installed, RealClientIP falls back to r.RemoteAddr —
// so callers that use RealClientIP are byte-identical to today's behaviour
// when no TrustedProxies middleware is in the chain.
type TrustedProxies struct {
	trusted []*net.IPNet
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
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipNet)
	}
	if hops <= 0 {
		hops = len(nets)
	}
	return &TrustedProxies{trusted: nets, hops: hops}, nil
}

// isTrusted reports whether ip falls within any of the trusted CIDRs.
func (tp *TrustedProxies) isTrusted(ip net.IP) bool {
	for _, n := range tp.trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// resolve derives the validated client IP for r. It parses the
// X-Forwarded-For header and walks right-to-left, skipping IPs that
// belong to trusted proxy CIDRs. The first IP that is either untrusted
// or immediately to the left of the last trusted hop (when the hops
// budget is exhausted) is returned as the real client IP.
//
// The hops budget prevents an operator misconfiguration (or an
// attacker with control of upstream trusted nodes) from peeling more
// proxy tiers than the deployment has: once the budget is consumed the
// walk stops and the entry to the left of the last trusted hop is
// returned, even if it is also in a trusted CIDR.
func (tp *TrustedProxies) resolve(r *http.Request) string {
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
		ip := net.ParseIP(raw)
		if ip == nil {
			// Unparseable hop — stop; the entry to our left is the client.
			if i > 0 {
				return strings.TrimSpace(parts[i-1])
			}
			return raw
		}
		if tp.isTrusted(ip) {
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

// Middleware wraps next, validates the X-Forwarded-For chain against the
// trusted CIDR list, and stores the validated real client IP in the
// request context so downstream consumers can retrieve it via RealClientIP.
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

// stripPort removes the :<port> suffix from a host:port address, returning
// just the host. IPv6 literals ([::1]:port) are handled correctly.
func stripPort(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
