package peertrust

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestRequestInfoRoundTrip(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	info := RequestInfo{ClientIP: "198.51.100.7", ForwardedHeadersTrusted: false}
	r = r.WithContext(WithRequestInfo(r.Context(), info))

	got, ok := RequestInfoFrom(r)
	if !ok || got != info {
		t.Fatalf("RequestInfoFrom = (%+v, %v), want (%+v, true)", got, ok, info)
	}
	if ForwardedHeadersTrusted(r) {
		t.Fatal("ForwardedHeadersTrusted = true, want false")
	}
}

func TestRequestInfoLegacyDefaults(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest("GET", "/", nil)
	if _, ok := RequestInfoFrom(r); ok {
		t.Fatal("request without middleware unexpectedly has RequestInfo")
	}
	if !ForwardedHeadersTrusted(r) || !ForwardedHeadersTrusted(nil) {
		t.Fatal("missing request info must preserve legacy forwarded-header trust")
	}
	if _, ok := RequestInfoFrom(nil); ok {
		t.Fatal("nil request unexpectedly has RequestInfo")
	}
	_ = WithRequestInfo(context.Background(), RequestInfo{})
}
