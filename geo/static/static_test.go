package static_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/geo/static"
)

func TestAdd_LookupRoundtrip(t *testing.T) {
	p := static.New()
	if err := p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := p.Lookup(context.Background(), net.ParseIP("10.5.6.7"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.CountryCode != "US" {
		t.Errorf("CountryCode=%q", got.CountryCode)
	}
}

func TestLookup_LongestPrefixWins(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", City: "broad"})
	_ = p.Add("10.1.0.0/16", geo.GeoInfo{CountryCode: "US", City: "narrow"})
	_ = p.Add("10.1.2.0/24", geo.GeoInfo{CountryCode: "US", City: "narrowest"})

	got, err := p.Lookup(context.Background(), net.ParseIP("10.1.2.3"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.City != "narrowest" {
		t.Errorf("City=%q want narrowest", got.City)
	}
}

func TestLookup_FallsThroughToBroaderEntry(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", City: "broad"})
	_ = p.Add("10.1.0.0/16", geo.GeoInfo{CountryCode: "US", City: "narrow"})

	// 10.2.x.x not covered by /16 → broader /8 wins.
	got, err := p.Lookup(context.Background(), net.ParseIP("10.2.0.1"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.City != "broad" {
		t.Errorf("City=%q want broad", got.City)
	}
}

func TestLookup_EmptyProviderReturnsErrNotFound(t *testing.T) {
	p := static.New()
	_, err := p.Lookup(context.Background(), net.ParseIP("10.0.0.1"))
	if !errors.Is(err, geo.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestLookup_NoMatchReturnsErrNotFound(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US"})
	_, err := p.Lookup(context.Background(), net.ParseIP("192.168.1.1"))
	if !errors.Is(err, geo.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestLookup_NilIPIsErrInvalidIP(t *testing.T) {
	p := static.New()
	_, err := p.Lookup(context.Background(), nil)
	if !errors.Is(err, geo.ErrInvalidIP) {
		t.Fatalf("err = %v", err)
	}
}

func TestAdd_RejectsBadCIDR(t *testing.T) {
	p := static.New()
	if err := p.Add("not-a-cidr", geo.GeoInfo{}); err == nil {
		t.Fatal("expected error")
	}
	if err := p.Add("", geo.GeoInfo{}); err == nil {
		t.Fatal("expected error for empty CIDR")
	}
}

func TestAdd_OverwritesSameCIDR(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", City: "v1"})
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", City: "v2"})
	if got := p.Len(); got != 1 {
		t.Errorf("Len after re-Add = %d, want 1", got)
	}
	info, _ := p.Lookup(context.Background(), net.ParseIP("10.0.0.1"))
	if info.City != "v2" {
		t.Errorf("City=%q want v2", info.City)
	}
}

func TestRemove_DropsEntry(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US"})
	if err := p.Remove("10.0.0.0/8"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if p.Len() != 0 {
		t.Errorf("Len after Remove = %d, want 0", p.Len())
	}
	if _, err := p.Lookup(context.Background(), net.ParseIP("10.0.0.1")); !errors.Is(err, geo.ErrNotFound) {
		t.Errorf("Lookup after Remove: %v", err)
	}
}

func TestRemove_MissingIsIdempotent(t *testing.T) {
	p := static.New()
	if err := p.Remove("10.0.0.0/8"); err != nil {
		t.Errorf("Remove on empty: %v", err)
	}
}

func TestRemove_RejectsBadCIDR(t *testing.T) {
	p := static.New()
	if err := p.Remove("not-a-cidr"); err == nil {
		t.Fatal("expected error for malformed CIDR")
	}
}

func TestRemove_LeavesOtherEntries(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US"})
	_ = p.Add("192.168.0.0/16", geo.GeoInfo{CountryCode: "US"})
	if err := p.Remove("10.0.0.0/8"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if p.Len() != 1 {
		t.Fatalf("Len = %d, want 1", p.Len())
	}
	if _, err := p.Lookup(context.Background(), net.ParseIP("192.168.1.1")); err != nil {
		t.Errorf("surviving entry lookup failed: %v", err)
	}
}

func TestLookup_IPv6(t *testing.T) {
	p := static.New()
	_ = p.Add("2001:db8::/32", geo.GeoInfo{CountryCode: "DE", RecommendedLanguage: "de-DE"})
	got, err := p.Lookup(context.Background(), net.ParseIP("2001:db8::1"))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.CountryCode != "DE" {
		t.Errorf("CountryCode=%q", got.CountryCode)
	}
}

func TestConcurrentLookupAndAdd_NoRace(t *testing.T) {
	// Race detector catches mutation-during-read; this just exercises
	// the path.
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US"})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = p.Lookup(context.Background(), net.ParseIP("10.0.0.1"))
		}()
		go func(i int) {
			defer wg.Done()
			cidr := "192.168." + string(rune('0'+(i%10))) + ".0/24"
			_ = p.Add(cidr, geo.GeoInfo{CountryCode: "US"})
		}(i)
	}
	wg.Wait()
}
