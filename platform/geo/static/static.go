// Package static is a CIDR-keyed in-memory geo.Provider. Operators
// curate the entries (private ranges, regional office blocks, key
// customer prefixes); the lookup is longest-prefix-match so a more
// specific entry overrides a broader one.
//
// Use this directly for tests + tiny operator-managed lookup tables,
// or stack it in front of a geo/maxmind Provider as an override
// layer (private RFC1918 ranges, internal ops networks the public
// DB doesn't know about) — see the doc on Provider.Lookup for the
// fall-through pattern.
package static

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"

	"github.com/yangwb1123/snaplink/platform/geo"
)

// Provider is a CIDR → GeoInfo lookup table. Safe for concurrent
// reads + writes. Entries are kept sorted by prefix length descending
// so Lookup can short-circuit on the first match (longest-prefix
// wins).
type Provider struct {
	mu      sync.RWMutex
	entries []entry
}

type entry struct {
	cidr string // canonical form, used for replace-on-Add
	net  *net.IPNet
	info geo.GeoInfo
}

// New returns an empty Provider.
func New() *Provider { return &Provider{} }

// Add registers info for the given CIDR. Re-Adding the same CIDR
// (in canonical form) overwrites the previous mapping; addresses
// covered by multiple entries pick the longest-prefix match.
func (p *Provider) Add(cidr string, info geo.GeoInfo) error {
	if cidr == "" {
		return errors.New("geo/static: empty CIDR")
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	canonical := n.String()

	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e.cidr == canonical {
			p.entries[i].info = info
			return nil
		}
	}
	p.entries = append(p.entries, entry{cidr: canonical, net: n, info: info})
	sort.SliceStable(p.entries, func(i, j int) bool {
		ai, _ := p.entries[i].net.Mask.Size()
		aj, _ := p.entries[j].net.Mask.Size()
		return ai > aj
	})
	return nil
}

// Remove drops the entry for the given CIDR. Idempotent — missing
// CIDR returns nil so reconciliation loops don't churn.
func (p *Provider) Remove(cidr string) error {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	canonical := n.String()
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.entries {
		if e.cidr == canonical {
			p.entries = append(p.entries[:i], p.entries[i+1:]...)
			return nil
		}
	}
	return nil
}

// Len reports how many entries are currently registered. Useful for
// metrics + a sanity-check after bulk loading.
func (p *Provider) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.entries)
}

func (p *Provider) Lookup(ctx context.Context, ip net.IP) (*geo.GeoInfo, error) {
	if ip == nil {
		return nil, geo.ErrInvalidIP
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, e := range p.entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if e.net.Contains(ip) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			cp := e.info
			return &cp, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, geo.ErrNotFound
}

// Compile-time interface check.
var _ geo.Provider = (*Provider)(nil)
