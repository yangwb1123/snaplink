package geo

import (
	"context"
	"testing"
)

func TestGeoContextRoundtrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	info := &GeoInfo{
		CountryCode: "US",
		Region:      "California",
		City:        "San Francisco",
	}

	// Store in context
	ctx = WithContext(ctx, info)

	// Retrieve from context
	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext() returned ok=false after WithContext")
	}
	if got.CountryCode != "US" {
		t.Errorf("CountryCode = %q, want US", got.CountryCode)
	}
	if got.City != "San Francisco" {
		t.Errorf("City = %q, want San Francisco", got.City)
	}
}

func TestGeoContextEmpty(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	_, ok := FromContext(ctx)
	if ok {
		t.Error("FromContext() on empty context returned ok=true")
	}
}

func TestGeoContextNilInfo(t *testing.T) {
	t.Parallel()

	ctx := WithContext(context.Background(), nil)
	got, ok := FromContext(ctx)
	if ok {
		t.Error("FromContext() after WithContext(nil) returned ok=true")
	}
	if got != nil {
		t.Errorf("FromContext() = %v, want nil", got)
	}
}

func TestGeoContextNilContext(t *testing.T) {
	t.Parallel()

	// FromContext must guard a nil ctx (callers chain unconditionally).
	got, ok := FromContext(context.TODO())
	if ok || got != nil {
		t.Errorf("FromContext(nil) = (%v, %v), want (nil, false)", got, ok)
	}
}

func TestWithContext_NilInfoReturnsSameContext(t *testing.T) {
	t.Parallel()

	// Passing nil info returns ctx unchanged so callers can chain.
	ctx := context.Background()
	if got := WithContext(ctx, nil); got != ctx {
		t.Error("WithContext(ctx, nil) returned a derived context, want ctx unchanged")
	}
}
