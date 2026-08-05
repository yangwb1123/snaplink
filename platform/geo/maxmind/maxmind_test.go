package maxmind

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/yangwb1123/snaplink/platform/geo"
	geostatic "github.com/yangwb1123/snaplink/platform/geo/static"
)

// buildFixture mints a small .mmdb with two test networks (TEST-NET-1 US,
// TEST-NET-2 DE) using the mmdbwriter — the deterministic way to get a valid
// database in a test without vendoring binary blobs.
func buildFixture(t *testing.T) []byte {
	t.Helper()
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: "GeoLite2-City",
		RecordSize:   24,
	})
	if err != nil {
		t.Fatalf("mmdbwriter: %v", err)
	}
	insert := func(cidr, country, region, city, tz string, lat, lon float64) {
		_, network, perr := net.ParseCIDR(cidr)
		if perr != nil {
			t.Fatal(perr)
		}
		if perr := tree.Insert(network, mmdbtype.Map{
			"country": mmdbtype.Map{"iso_code": mmdbtype.String(country)},
			"subdivisions": mmdbtype.Slice{
				mmdbtype.Map{"iso_code": mmdbtype.String(region)},
			},
			"city": mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String(city)}},
			"location": mmdbtype.Map{
				"latitude":  mmdbtype.Float64(lat),
				"longitude": mmdbtype.Float64(lon),
				"time_zone": mmdbtype.String(tz),
			},
		}); perr != nil {
			t.Fatalf("insert %s: %v", cidr, perr)
		}
	}
	insert("8.8.8.0/24", "US", "CA", "Testville", "America/Los_Angeles", 34.05, -118.24)
	insert("1.1.1.0/24", "DE", "BE", "Berlin", "Europe/Berlin", 52.52, 13.40)
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatalf("write mmdb: %v", err)
	}
	return buf.Bytes()
}

func TestProvider_LookupAndMiss(t *testing.T) {
	t.Parallel()
	p, err := New(buildFixture(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	info, err := p.Lookup(context.Background(), net.ParseIP("8.8.8.7"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info.CountryCode != "US" || info.Region != "CA" || info.City != "Testville" {
		t.Errorf("info = %+v, want US/CA/Testville", info)
	}
	if info.TimeZone != "America/Los_Angeles" || info.Latitude == 0 {
		t.Errorf("location fields = %+v", info)
	}
	// Unknown IP (not in the fixture): ErrNotFound, not an error.
	if _, err := p.Lookup(context.Background(), net.ParseIP("203.0.113.99")); !errors.Is(err, geo.ErrNotFound) {
		t.Errorf("miss = %v, want ErrNotFound", err)
	}
}

func TestProvider_NewRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) must fail")
	}
}

func TestProvider_ReplaceIsAtomicAndFailOpen(t *testing.T) {
	t.Parallel()
	p, err := New(buildFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// Replace with a DE-only database (fixture without the US network).
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-City", RecordSize: 24})
	if err != nil {
		t.Fatal(err)
	}
	_, network, _ := net.ParseCIDR("1.1.1.0/24")
	if err := tree.Insert(network, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("DE")}}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := tree.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	if err := p.Replace(buf.Bytes()); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if _, err := p.Lookup(context.Background(), net.ParseIP("8.8.8.7")); !errors.Is(err, geo.ErrNotFound) {
		t.Errorf("US IP still resolves after replace: %v", err)
	}
	info, err := p.Lookup(context.Background(), net.ParseIP("1.1.1.5"))
	if err != nil || info.CountryCode != "DE" {
		t.Errorf("DE IP after replace = %+v, %v", info, err)
	}

	// A failed replacement leaves the OLD database serving.
	if err := p.Replace([]byte("not a mmdb")); err == nil {
		t.Fatal("Replace(garbage) must fail")
	}
	if info, err := p.Lookup(context.Background(), net.ParseIP("1.1.1.5")); err != nil || info.CountryCode != "DE" {
		t.Errorf("old DB not serving after failed replace: %+v, %v", info, err)
	}
}

func TestComposite_StaticOverridesMaxmind(t *testing.T) {
	t.Parallel()
	primary, err := New(buildFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	overrides := geostatic.New()
	// Override TEST-NET-3 (not in the fixture) as GB, and shadow a fixture
	// network: 198.51.100.0/24 re-pinned to GB (static wins over primary).
	if err := overrides.Add("1.1.1.0/24", geo.GeoInfo{CountryCode: "GB"}); err != nil {
		t.Fatal(err)
	}
	if err := overrides.Add("9.9.9.0/24", geo.GeoInfo{CountryCode: "JP"}); err != nil {
		t.Fatal(err)
	}
	c := geo.NewComposite(overrides, primary)

	// Override-only range: JP from the static layer.
	info, err := c.Lookup(context.Background(), net.ParseIP("9.9.9.10"))
	if err != nil || info.CountryCode != "JP" {
		t.Errorf("override range = %+v, %v; want JP", info, err)
	}
	// Shadowed range: static GB wins over the primary's DE.
	info, err = c.Lookup(context.Background(), net.ParseIP("1.1.1.10"))
	if err != nil || info.CountryCode != "GB" {
		t.Errorf("shadowed range = %+v, %v; want GB (static wins)", info, err)
	}
	// Primary-only range: US from the mmdb.
	info, err = c.Lookup(context.Background(), net.ParseIP("8.8.8.10"))
	if err != nil || info.CountryCode != "US" {
		t.Errorf("primary range = %+v, %v; want US", info, err)
	}
	// Complete miss: ErrNotFound.
	if _, err := c.Lookup(context.Background(), net.ParseIP("10.0.0.1")); !errors.Is(err, geo.ErrNotFound) {
		t.Errorf("miss = %v, want ErrNotFound", err)
	}
}
