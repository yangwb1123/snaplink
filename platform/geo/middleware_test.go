package geo_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/platform/geo/static"
	"github.com/snaplink/sso/shared/core"
)

// blockingProvider stalls Lookup until ctx is cancelled, then surfaces the
// ctx error. Used to drive the middleware's per-lookup timeout / fail-open
// path without a real network backend (no mocks — this is a real Provider).
type blockingProvider struct{}

func (blockingProvider) Lookup(ctx context.Context, _ net.IP) (*geo.GeoInfo, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// errProvider always fails with a non-ErrNotFound error so the OnError hook
// fires.
type errProvider struct{ err error }

func (e errProvider) Lookup(context.Context, net.IP) (*geo.GeoInfo, error) {
	return nil, e.err
}

// notFoundProvider always returns ErrNotFound (the normal "unknown IP" case).
type notFoundProvider struct{}

func (notFoundProvider) Lookup(context.Context, net.IP) (*geo.GeoInfo, error) {
	return nil, geo.ErrNotFound
}

// nilInfoProvider returns (nil, nil): no error, but no info either. The
// middleware must not stash a nil *GeoInfo.
type nilInfoProvider struct{}

func (nilInfoProvider) Lookup(context.Context, net.IP) (*geo.GeoInfo, error) {
	return nil, nil
}

// newHCtx builds a *core.Context (a HandlerContext) for the request, the way
// the router does, so the middleware's value-bag Set/Get round-trips.
func newHCtx(r *http.Request) *core.Context {
	return core.NewContext(httptest.NewRecorder(), r)
}

func requestWithRemoteAddr(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestMiddleware_EnrichSuccess(t *testing.T) {
	p := static.New()
	if err := p.Add("203.0.113.0/24", geo.GeoInfo{
		CountryCode:         "US",
		RecommendedLanguage: "en-US",
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	mw := geo.Middleware(p, geo.MiddlewareOptions{})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:54321"))
	mw(hctx)

	info, ok := geo.FromHandlerContext(hctx)
	if !ok {
		t.Fatal("FromHandlerContext ok=false after successful enrich")
	}
	if info.CountryCode != "US" || info.RecommendedLanguage != "en-US" {
		t.Errorf("got %+v", info)
	}
}

func TestMiddleware_NilProviderIsNoOp(t *testing.T) {
	mw := geo.Middleware(nil, geo.MiddlewareOptions{})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx) // must not panic and must not stash anything

	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("nil-provider middleware stashed geo info")
	}
}

func TestMiddleware_MissingIPSkipsLookup(t *testing.T) {
	// Extractor returns nil → middleware short-circuits before Lookup. Use a
	// provider that would error if reached, to prove it is not reached.
	called := false
	p := errProvider{err: errors.New("must not be called")}
	mw := geo.Middleware(p, geo.MiddlewareOptions{
		IPExtractor: func(*http.Request) net.IP { return nil },
		OnError:     func(error) { called = true },
	})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx)

	if called {
		t.Error("OnError fired despite nil IP (lookup should have been skipped)")
	}
	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("stashed geo info despite nil IP")
	}
}

func TestMiddleware_LookupErrorFailsOpenAndReportsViaOnError(t *testing.T) {
	wantErr := errors.New("backend down")
	var gotErr error
	mw := geo.Middleware(errProvider{err: wantErr}, geo.MiddlewareOptions{
		OnError: func(err error) { gotErr = err },
	})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx) // fail-open: must not panic, must not stash

	if !errors.Is(gotErr, wantErr) {
		t.Errorf("OnError got %v, want %v", gotErr, wantErr)
	}
	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("stashed geo info despite lookup error")
	}
}

func TestMiddleware_NotFoundIsSilent(t *testing.T) {
	// ErrNotFound is the normal "unknown IP" outcome and MUST NOT trip OnError.
	reported := false
	mw := geo.Middleware(notFoundProvider{}, geo.MiddlewareOptions{
		OnError: func(error) { reported = true },
	})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx)

	if reported {
		t.Error("OnError fired for ErrNotFound (should be silent)")
	}
	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("stashed geo info for ErrNotFound")
	}
}

func TestMiddleware_LookupErrorWithoutOnErrorDoesNotPanic(t *testing.T) {
	// OnError unset: the error path must still fail-open cleanly.
	mw := geo.Middleware(errProvider{err: errors.New("boom")}, geo.MiddlewareOptions{})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx)

	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("stashed geo info despite lookup error")
	}
}

func TestMiddleware_NilInfoNotStashed(t *testing.T) {
	mw := geo.Middleware(nilInfoProvider{}, geo.MiddlewareOptions{})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx)

	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("stashed a nil *GeoInfo")
	}
}

func TestMiddleware_TimeoutFailsOpen(t *testing.T) {
	// A blocking provider plus a tiny timeout exercises the
	// context.WithTimeout branch: the lookup returns ctx.Err() and the
	// middleware fails open. OnError SHOULD fire (ctx err is not ErrNotFound).
	var gotErr error
	start := time.Now()
	mw := geo.Middleware(blockingProvider{}, geo.MiddlewareOptions{
		Timeout: 20 * time.Millisecond,
		OnError: func(err error) { gotErr = err },
	})
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	mw(hctx)

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("middleware blocked %v — timeout not honored", elapsed)
	}
	if gotErr == nil || !errors.Is(gotErr, context.DeadlineExceeded) {
		t.Errorf("OnError got %v, want DeadlineExceeded", gotErr)
	}
	if _, ok := geo.FromHandlerContext(hctx); ok {
		t.Error("stashed geo info despite timeout")
	}
}

func TestMiddleware_CustomExtractorIsUsed(t *testing.T) {
	p := static.New()
	_ = p.Add("198.51.100.0/24", geo.GeoInfo{CountryCode: "CA"})

	mw := geo.Middleware(p, geo.MiddlewareOptions{
		// Ignore the request entirely; return a fixed in-range IP.
		IPExtractor: func(*http.Request) net.IP { return net.ParseIP("198.51.100.7") },
	})
	hctx := newHCtx(requestWithRemoteAddr("10.0.0.1:1234"))
	mw(hctx)

	info, ok := geo.FromHandlerContext(hctx)
	if !ok {
		t.Fatal("custom extractor result not used")
	}
	if info.CountryCode != "CA" {
		t.Errorf("CountryCode=%q want CA", info.CountryCode)
	}
}

func TestMiddleware_ZeroValueOptionsUseDefaults(t *testing.T) {
	// Zero MiddlewareOptions → DefaultIPExtractor + DefaultLookupTimeout.
	// Drive it through a forwarded header to confirm the default extractor ran.
	p := static.New()
	_ = p.Add("192.0.2.0/24", geo.GeoInfo{CountryCode: "US", City: "doc"})

	mw := geo.Middleware(p, geo.MiddlewareOptions{})
	r := requestWithRemoteAddr("10.0.0.1:1234")
	r.Header.Set("X-Forwarded-For", "192.0.2.10")
	hctx := newHCtx(r)
	mw(hctx)

	info, ok := geo.FromHandlerContext(hctx)
	if !ok {
		t.Fatal("default extractor did not honor X-Forwarded-For")
	}
	if info.City != "doc" {
		t.Errorf("City=%q want doc", info.City)
	}
}

func TestFromHandlerContext_NilContext(t *testing.T) {
	if info, ok := geo.FromHandlerContext(nil); ok || info != nil {
		t.Errorf("FromHandlerContext(nil) = (%v, %v), want (nil, false)", info, ok)
	}
}

func TestFromHandlerContext_MissingKey(t *testing.T) {
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	if info, ok := geo.FromHandlerContext(hctx); ok || info != nil {
		t.Errorf("FromHandlerContext with no value = (%v, %v), want (nil, false)", info, ok)
	}
}

func TestFromHandlerContext_WrongType(t *testing.T) {
	// A non-*GeoInfo stashed under the key must yield (nil, false), not panic.
	hctx := newHCtx(requestWithRemoteAddr("203.0.113.5:1234"))
	hctx.Set(geo.HandlerContextKey, "not a geoinfo")
	if info, ok := geo.FromHandlerContext(hctx); ok || info != nil {
		t.Errorf("FromHandlerContext wrong type = (%v, %v), want (nil, false)", info, ok)
	}
}

func TestDefaultIPExtractor_ForwardedForFirstHop(t *testing.T) {
	r := requestWithRemoteAddr("10.0.0.1:9999")
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 70.41.3.18, 150.172.238.178")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "203.0.113.7" {
		t.Errorf("got %v, want 203.0.113.7 (first hop)", got)
	}
}

func TestDefaultIPExtractor_ForwardedForSingleValueTrimmed(t *testing.T) {
	r := requestWithRemoteAddr("10.0.0.1:9999")
	r.Header.Set("X-Forwarded-For", "  203.0.113.9  ")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "203.0.113.9" {
		t.Errorf("got %v, want 203.0.113.9", got)
	}
}

func TestDefaultIPExtractor_InvalidForwardedForFallsToRealIP(t *testing.T) {
	r := requestWithRemoteAddr("10.0.0.1:9999")
	r.Header.Set("X-Forwarded-For", "garbage")
	r.Header.Set("X-Real-IP", "198.51.100.22")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "198.51.100.22" {
		t.Errorf("got %v, want 198.51.100.22 (X-Real-IP fallback)", got)
	}
}

func TestDefaultIPExtractor_RealIP(t *testing.T) {
	r := requestWithRemoteAddr("10.0.0.1:9999")
	r.Header.Set("X-Real-IP", "  198.51.100.5 ")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "198.51.100.5" {
		t.Errorf("got %v, want 198.51.100.5", got)
	}
}

func TestDefaultIPExtractor_InvalidRealIPFallsToRemoteAddr(t *testing.T) {
	r := requestWithRemoteAddr("192.0.2.44:5555")
	r.Header.Set("X-Real-IP", "not-an-ip")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "192.0.2.44" {
		t.Errorf("got %v, want 192.0.2.44 (RemoteAddr fallback)", got)
	}
}

func TestDefaultIPExtractor_RemoteAddrWithPort(t *testing.T) {
	r := requestWithRemoteAddr("192.0.2.55:443")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "192.0.2.55" {
		t.Errorf("got %v, want 192.0.2.55", got)
	}
}

func TestDefaultIPExtractor_RemoteAddrWithoutPort(t *testing.T) {
	// Rare: some test harnesses set a bare IP with no port.
	r := requestWithRemoteAddr("192.0.2.66")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "192.0.2.66" {
		t.Errorf("got %v, want 192.0.2.66", got)
	}
}

func TestDefaultIPExtractor_IPv6RemoteAddr(t *testing.T) {
	r := requestWithRemoteAddr("[2001:db8::1]:8443")
	got := geo.DefaultIPExtractor(r)
	if got == nil || got.String() != "2001:db8::1" {
		t.Errorf("got %v, want 2001:db8::1", got)
	}
}

func TestDefaultIPExtractor_NoUsableSourceReturnsNil(t *testing.T) {
	r := requestWithRemoteAddr("")
	if got := geo.DefaultIPExtractor(r); got != nil {
		t.Errorf("got %v, want nil when no IP source present", got)
	}
}

func TestDefaultIPExtractor_GarbageRemoteAddrReturnsNil(t *testing.T) {
	r := requestWithRemoteAddr("totally:not:valid:addr")
	if got := geo.DefaultIPExtractor(r); got != nil {
		t.Errorf("got %v, want nil for unparseable RemoteAddr", got)
	}
}
