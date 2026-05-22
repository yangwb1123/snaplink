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
)

// GeoInfo is one IP's geo lookup result. All fields are optional —
// backends may know the country but not the city, the city but not
// the timezone, etc. RecommendedLanguage is a BCP-47 tag (e.g.
// "en-US", "zh-CN", "de-DE"); empty when no mapping is known.
type GeoInfo struct {
	CountryCode         string `json:"country_code,omitempty"` // ISO 3166-1 alpha-2 ("US", "CN")
	Region              string `json:"region,omitempty"`       // ISO 3166-2 subdivision ("US-CA")
	City                string `json:"city,omitempty"`
	TimeZone            string `json:"time_zone,omitempty"`            // IANA tz database id
	RecommendedLanguage string `json:"recommended_language,omitempty"` // BCP-47

	// Latitude + Longitude in decimal degrees, populated when the
	// provider has lat/lon data (MaxMind GeoIP2 City, ipgeolocation.io,
	// most commercial DBs). Both zero = unknown; consumers MUST
	// NOT treat (0,0) as the Gulf of Guinea. Used by the
	// impossible-travel anomaly detector — provider impls without
	// lat/lon (`geo/static` shipped CIDR list) leave these zero
	// and the detector skips the distance check.
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
}

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
