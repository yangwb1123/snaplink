// Package geo is the IP → geo enrichment SPI consumed by the SSO
// auth path. Lookup happens early in request handling; the result is
// stashed in request context so handlers + authenticators can pull
// out a recommended language for the response, route SMS by region,
// or skip MFA from a known office IP.
//
// The SPI is intentionally read-only and minimal — geo is a UX hint,
// not a security boundary. Production deployments wanting full IP
// coverage should use geo/maxmind on top of a curated geo/static
// for private-range overrides; the static Provider alone is fine
// for tests + small operator-managed lookup tables.
//
// Implementations live in geo/<backend>/. ErrNotFound is the
// expected outcome for unknown IPs (private ranges, unallocated
// blocks, brand-new prefixes); callers SHOULD treat it as "no
// hint, fall through to defaults" rather than failing the request.
package geo

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/snaplink/sso/shared/core"
)

// GeoInfo is an alias for [core.GeoInfo]. The type was relocated to core (the
// dependency-free leaf) so the spi.RiskScorer request and the anomaly
// LoginEvent can carry geo data without importing this package — that kept geo
// out of the widely-imported spi kernel (a layering inversion). The alias keeps
// geo.GeoInfo a valid, byte-identical type for every existing consumer.
type GeoInfo = core.GeoInfo

// Provider looks up GeoInfo for an IP address. Implementations must
// be safe for concurrent use — Lookup is called on the request hot
// path and will see fan-out from the SSO server.
//
// Returning ErrNotFound is normal and not an error condition; only
// return other errors when the lookup itself failed (DB closed,
// network timeout to an external service, etc).
type Provider interface {
	Lookup(ctx context.Context, ip net.IP) (*GeoInfo, error)
}

// Sentinel errors. Callers branch on these via errors.Is.
var (
	ErrNotFound  = errors.New("geo: not found")
	ErrInvalidIP = errors.New("geo: invalid IP")
)

// LookupString is a convenience for the common case where the IP
// arrives as a string (X-Forwarded-For header value, the host part
// of net.SplitHostPort on RemoteAddr, etc). Returns ErrInvalidIP
// wrapping the raw input when net.ParseIP rejects it.
func LookupString(ctx context.Context, p Provider, raw string) (*GeoInfo, error) {
	if p == nil {
		return nil, errors.New("geo: nil provider")
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidIP, raw)
	}
	return p.Lookup(ctx, ip)
}
