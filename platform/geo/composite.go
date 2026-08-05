package geo

import (
	"context"
	"net"
)

// Composite stacks an override Provider (typically geo/static, for
// operator-curated private/office ranges) in front of a primary Provider
// (typically geo/maxmind, for full public-IP coverage): the override wins
// for ranges it knows, everything else falls through to the primary. This is
// the composition the package doc recommends — the static table's
// longest-prefix semantics are preserved within its own layer, and the
// primary's misses surface as the standard ErrNotFound.
//
// Both providers may be nil-safe: a nil override delegates entirely to the
// primary; a nil primary means the override is the whole answer (an
// override miss becomes ErrNotFound). Safe for concurrent use when both
// providers are.
type Composite struct {
	overrides Provider
	primary   Provider
}

// NewComposite builds the stacked provider.
func NewComposite(overrides, primary Provider) *Composite {
	return &Composite{overrides: overrides, primary: primary}
}

// Lookup implements Provider: override first, then primary. An override
// hit is authoritative; any other override outcome (miss or error) falls
// through to the primary, whose ErrNotFound is the composite's miss.
func (c *Composite) Lookup(ctx context.Context, ip net.IP) (*GeoInfo, error) {
	if c.overrides != nil {
		if info, err := c.overrides.Lookup(ctx, ip); err == nil {
			return info, nil
		}
	}
	if c.primary != nil {
		return c.primary.Lookup(ctx, ip)
	}
	return nil, ErrNotFound
}
