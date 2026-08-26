// Package maxmind is a production IP-coverage geo.Provider backed by a
// MaxMind GeoLite2/GeoIP2 .mmdb database (City or Country), the backend the
// geo package doc names for full coverage. The database is loaded into an
// in-memory snapshot that Lookup reads through an atomic pointer, so
// Replace can swap in a refreshed database while concurrent requests keep
// seeing either the old or the new snapshot — never a half-read state.
//
// Stack it behind a geo/static Provider for private-range overrides (the
// static doc's recommended composition): the static table wins for the
// ranges operators curate, the mmdb covers everything else. Lookup follows
// the geo.Provider contract — ErrNotFound for misses (private ranges,
// unallocated blocks), never a request failure.
//
// Data freshness is the operator's contract (download + checksum + Replace
// via a refresh task or admin command); a stale database still serves
// correctly (fail-open — the lookup result is a hint, not a gate).
package maxmind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/oschwald/maxminddb-golang"
	"github.com/yangwb1123/snaplink/platform/geo"
)

// geoRecord is the subset of the GeoIP2 City schema the SPI exposes.
type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
		TimeZone  string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

// Provider is the .mmdb-backed geo.Provider. Safe for concurrent Lookup and
// Replace.
type Provider struct {
	db atomic.Pointer[maxminddb.Reader]
}

// New loads the database bytes into a fresh Provider. A nil/empty database
// is rejected (a provider that can never answer is a wiring error, not a
// lookup miss).
func New(database []byte) (*Provider, error) {
	if len(database) == 0 {
		return nil, errors.New("geo/maxmind: empty database")
	}
	r, err := maxminddb.FromBytes(database)
	if err != nil {
		return nil, fmt.Errorf("geo/maxmind: parse database: %w", err)
	}
	p := &Provider{}
	p.db.Store(r)
	return p, nil
}

// Replace atomically swaps in a refreshed database. The previous snapshot
// stays readable by in-flight Lookups until they finish. A failed parse
// leaves the OLD database serving (fail-open: a bad download must not take
// geo enrichment down).
func (p *Provider) Replace(database []byte) error {
	r, err := maxminddb.FromBytes(database)
	if err != nil {
		return fmt.Errorf("geo/maxmind: parse replacement database: %w", err)
	}
	old := p.db.Swap(r)
	if old != nil {
		_ = old.Close()
	}
	return nil
}

// Lookup implements geo.Provider. Returns geo.ErrNotFound for IPs the
// database has no record for (the mmdb reader's ErrNotFound).
func (p *Provider) Lookup(ctx context.Context, ip net.IP) (*geo.GeoInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := p.db.Load()
	if r == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, geo.ErrNotFound
	}
	var rec geoRecord
	lookupErr := r.Lookup(ip, &rec)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lookupErr != nil {
		// The reader returns nil error + an untouched zeroed record for a
		// miss (no record matches); a non-nil error is a real failure.
		return nil, fmt.Errorf("geo/maxmind: lookup: %w", lookupErr)
	}
	info := &geo.GeoInfo{
		CountryCode: rec.Country.ISOCode,
		Latitude:    rec.Location.Latitude,
		Longitude:   rec.Location.Longitude,
		TimeZone:    rec.Location.TimeZone,
	}
	if len(rec.Subdivisions) > 0 {
		info.Region = rec.Subdivisions[0].ISOCode
	}
	if name := rec.City.Names["en"]; name != "" {
		info.City = name
	}
	if info.CountryCode == "" && info.City == "" && info.Region == "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, geo.ErrNotFound
	}
	return info, nil
}
