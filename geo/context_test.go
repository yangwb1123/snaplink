package geo_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/geo"
)

func TestWithContext_RoundTrip(t *testing.T) {
	info := &geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"}
	ctx := geo.WithContext(context.Background(), info)
	got, ok := geo.FromContext(ctx)
	if !ok {
		t.Fatal("FromContext returned !ok")
	}
	if got.CountryCode != "US" || got.RecommendedLanguage != "en-US" {
		t.Errorf("got %+v", got)
	}
}

func TestWithContext_NilInfoIsIdentity(t *testing.T) {
	base := context.Background()
	if got := geo.WithContext(base, nil); got != base {
		t.Error("WithContext(ctx, nil) should return ctx unchanged")
	}
}

func TestFromContext_NoValue(t *testing.T) {
	_, ok := geo.FromContext(context.Background())
	if ok {
		t.Error("FromContext on empty context returned ok=true")
	}
}

func TestFromContext_NilContext(t *testing.T) {
	// FromContext documents that it tolerates a nil ctx — exercise that
	// branch explicitly. Using a typed nil variable keeps staticcheck
	// (SA1012) quiet while still passing a nil through the SPI.
	var nilCtx context.Context //nolint:staticcheck
	_, ok := geo.FromContext(nilCtx)
	if ok {
		t.Error("FromContext(nil) returned ok=true")
	}
}

func TestWithContext_KeyIsolation(t *testing.T) {
	// Stash a *GeoInfo under a different key shape — FromContext must
	// NOT pick it up. This guards against accidental key collisions.
	type someoneElsesKey struct{}
	ctx := context.WithValue(context.Background(), someoneElsesKey{}, &geo.GeoInfo{CountryCode: "DE"})
	_, ok := geo.FromContext(ctx)
	if ok {
		t.Error("FromContext picked up a value stored under a different key")
	}
}
