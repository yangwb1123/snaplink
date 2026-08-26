package geo_test

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/platform/geo/static"
)

func TestLookupString_HappyPath(t *testing.T) {
	t.Parallel()
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	got, err := geo.LookupString(context.Background(), p, "10.1.2.3")
	if err != nil {
		t.Fatalf("LookupString: %v", err)
	}
	if got.CountryCode != "US" || got.RecommendedLanguage != "en-US" {
		t.Errorf("got %+v", got)
	}
}

func TestLookupString_RejectsBadIP(t *testing.T) {
	t.Parallel()
	p := static.New()
	_, err := geo.LookupString(context.Background(), p, "not-an-ip")
	if !errors.Is(err, geo.ErrInvalidIP) {
		t.Fatalf("err = %v, want ErrInvalidIP", err)
	}
}

func TestLookupString_NilProviderIsError(t *testing.T) {
	t.Parallel()
	if _, err := geo.LookupString(context.Background(), nil, "10.0.0.1"); err == nil {
		t.Fatal("expected error for nil provider")
	}
}

func TestLookupString_PropagatesNotFound(t *testing.T) {
	t.Parallel()
	p := static.New()
	_, err := geo.LookupString(context.Background(), p, "10.0.0.1")
	if !errors.Is(err, geo.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

type recordingProvider struct {
	got  context.Context
	info *geo.GeoInfo
	err  error
}

func (p *recordingProvider) Lookup(ctx context.Context, _ net.IP) (*geo.GeoInfo, error) {
	p.got = ctx
	return p.info, p.err
}

// asProvider verifies the static.Provider satisfies geo.Provider at runtime
// (the compile-time check lives next to the type; this exercises the path
// via the SPI).
func TestStaticImplementsProvider(t *testing.T) {
	t.Parallel()
	var p geo.Provider = static.New()
	_, _ = p.Lookup(context.Background(), net.ParseIP("127.0.0.1"))
}

func TestComposite_PassesContextToBothProviders(t *testing.T) {
	t.Parallel()
	want := context.WithValue(context.Background(), "geo-test", "context")
	override := &recordingProvider{err: geo.ErrNotFound}
	primary := &recordingProvider{info: &geo.GeoInfo{CountryCode: "US"}}

	info, err := geo.NewComposite(override, primary).Lookup(want, net.ParseIP("203.0.113.5"))
	if err != nil || info.CountryCode != "US" {
		t.Fatalf("Lookup = %+v, %v; want primary result", info, err)
	}
	if override.got != want {
		t.Error("override did not receive the original context")
	}
	if primary.got != want {
		t.Error("primary did not receive the original context")
	}
}
