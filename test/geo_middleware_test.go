package ssotest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/platform/geo/static"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
)

// stubProvider always returns the configured info / err. Used to
// drive specific middleware-path tests without standing up a real
// CIDR lookup table.
type stubProvider struct {
	info *geo.GeoInfo
	err  error
	last net.IP
}

func (p *stubProvider) Lookup(_ context.Context, ip net.IP) (*geo.GeoInfo, error) {
	p.last = ip
	return p.info, p.err
}

func newCtx(t *testing.T, r *http.Request) sso.HandlerContext {
	t.Helper()
	rec := httptest.NewRecorder()
	return sso.NewContext(rec, r)
}

func TestGeoMiddleware_PopulatesHandlerContext(t *testing.T) {
	want := &geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"}
	mw := sso.GeoMiddleware(&stubProvider{info: want}, sso.GeoMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	hctx := newCtx(t, r)
	mw(hctx)

	got, ok := sso.GeoFromHandlerContext(hctx)
	if !ok {
		t.Fatal("FromHandlerContext returned !ok after successful Lookup")
	}
	if got.CountryCode != "US" || got.RecommendedLanguage != "en-US" {
		t.Errorf("got %+v", got)
	}
}

func TestGeoMiddleware_NotFoundLeavesContextEmpty(t *testing.T) {
	mw := sso.GeoMiddleware(&stubProvider{err: geo.ErrNotFound}, sso.GeoMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	hctx := newCtx(t, r)
	mw(hctx)
	if _, ok := sso.GeoFromHandlerContext(hctx); ok {
		t.Error("ErrNotFound should leave context empty")
	}
}

func TestGeoMiddleware_NoIPSkipsLookup(t *testing.T) {
	stub := &stubProvider{info: &geo.GeoInfo{CountryCode: "US"}}
	mw := sso.GeoMiddleware(stub, sso.GeoMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "" // no IP to extract
	hctx := newCtx(t, r)
	mw(hctx)
	if stub.last != nil {
		t.Errorf("Lookup called with %v despite no extractable IP", stub.last)
	}
}

func TestGeoMiddleware_NilProviderIsNoop(t *testing.T) {
	mw := sso.GeoMiddleware(nil, sso.GeoMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	hctx := newCtx(t, r)
	mw(hctx) // should not panic
	if _, ok := sso.GeoFromHandlerContext(hctx); ok {
		t.Error("nil provider should leave context empty")
	}
}

func TestGeoMiddleware_OnErrorFiresOnNonSentinel(t *testing.T) {
	wantErr := errors.New("backend down")
	var captured error
	mw := sso.GeoMiddleware(&stubProvider{err: wantErr}, sso.GeoMiddlewareOptions{
		OnError: func(err error) { captured = err },
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	mw(newCtx(t, r))
	if !errors.Is(captured, wantErr) {
		t.Errorf("OnError captured = %v, want wantErr", captured)
	}
}

func TestGeoMiddleware_OnErrorSkipsSentinels(t *testing.T) {
	var captured error
	mw := sso.GeoMiddleware(&stubProvider{err: geo.ErrNotFound}, sso.GeoMiddlewareOptions{
		OnError: func(err error) { captured = err },
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	mw(newCtx(t, r))
	if captured != nil {
		t.Errorf("ErrNotFound should not fire OnError; got %v", captured)
	}
}

func TestGeoMiddleware_TimeoutBoundsLookup(t *testing.T) {
	// Provider that respects context cancellation.
	slow := &slowProvider{delay: 500 * time.Millisecond}
	mw := sso.GeoMiddleware(slow, sso.GeoMiddlewareOptions{Timeout: 10 * time.Millisecond})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	start := time.Now()
	mw(newCtx(t, r))
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("middleware blocked %v despite 10ms timeout", elapsed)
	}
}

type slowProvider struct {
	delay time.Duration
}

func (p *slowProvider) Lookup(ctx context.Context, _ net.IP) (*geo.GeoInfo, error) {
	select {
	case <-time.After(p.delay):
		return &geo.GeoInfo{CountryCode: "US"}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestGeoMiddleware_E2EWithStaticProvider(t *testing.T) {
	p := static.New()
	_ = p.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", RecommendedLanguage: "en-US"})
	mw := sso.GeoMiddleware(p, sso.GeoMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.5.6.7:1234"
	hctx := newCtx(t, r)
	mw(hctx)
	got, ok := sso.GeoFromHandlerContext(hctx)
	if !ok || got.CountryCode != "US" || got.RecommendedLanguage != "en-US" {
		t.Errorf("e2e got=%+v ok=%v", got, ok)
	}
}

func TestDefaultGeoIPExtractor_PeerTrustGate(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*http.Request)
		want  string
	}{
		{
			name: "trusted canonical peer wins",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "9.9.9.9")
				r.RemoteAddr = "127.0.0.1:1234"
				*r = *withPeerTrust(r, peertrust.RequestInfo{
					ClientIP: "1.2.3.4", ForwardedHeadersTrusted: true,
				})
			},
			want: "1.2.3.4",
		},
		{
			name: "untrusted canonical peer is used",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "9.9.9.9")
				r.Header.Set("X-Real-IP", "8.8.8.8")
				r.RemoteAddr = "192.0.2.1:1234"
				*r = *withPeerTrust(r, peertrust.RequestInfo{
					ClientIP: "192.0.2.1", ForwardedHeadersTrusted: false,
				})
			},
			want: "192.0.2.1",
		},
		{
			name: "without context ignores forged headers",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "1.2.3.4")
				r.Header.Set("X-Real-IP", "5.6.7.8")
				r.RemoteAddr = "192.0.2.2:1234"
			},
			want: "192.0.2.2",
		},
		{
			name: "empty canonical falls back to remote",
			setup: func(r *http.Request) {
				r.Header.Set("X-Real-IP", "5.6.7.8")
				r.RemoteAddr = "192.0.2.3:1234"
				*r = *withPeerTrust(r, peertrust.RequestInfo{})
			},
			want: "192.0.2.3",
		},
		{
			name: "invalid canonical falls back to remote",
			setup: func(r *http.Request) {
				r.Header.Set("X-Forwarded-For", "5.6.7.8")
				r.RemoteAddr = "192.0.2.4:1234"
				*r = *withPeerTrust(r, peertrust.RequestInfo{ClientIP: "bad-ip"})
			},
			want: "192.0.2.4",
		},
		{
			name:  "remoteaddr without port",
			setup: func(r *http.Request) { r.RemoteAddr = "192.168.1.1" },
			want:  "192.168.1.1",
		},
		{
			name:  "ipv6 remoteaddr",
			setup: func(r *http.Request) { r.RemoteAddr = "[::1]:8080" },
			want:  "::1",
		},
		{
			name:  "no remote returns nil",
			setup: func(r *http.Request) { r.RemoteAddr = "" },
			want:  "",
		},
		{
			name:  "invalid remote returns nil",
			setup: func(r *http.Request) { r.RemoteAddr = "not-an-ip" },
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			tc.setup(r)
			got := sso.DefaultGeoIPExtractor(r)
			if tc.want == "" {
				if got != nil {
					t.Errorf("got %v want nil", got)
				}
				return
			}
			if got == nil || got.String() != tc.want {
				t.Errorf("got %v want %s", got, tc.want)
			}
		})
	}
}

func withPeerTrust(r *http.Request, info peertrust.RequestInfo) *http.Request {
	return r.WithContext(peertrust.WithRequestInfo(r.Context(), info))
}

func TestGeoFromHandlerContext_NilContext(t *testing.T) {
	if _, ok := sso.GeoFromHandlerContext(nil); ok {
		t.Error("nil HandlerContext should return false")
	}
}

func TestGeoWithContext_RoundTrip(t *testing.T) {
	want := &geo.GeoInfo{CountryCode: "DE"}
	ctx := geo.WithContext(context.Background(), want)
	got, ok := geo.FromContext(ctx)
	if !ok || got.CountryCode != "DE" {
		t.Errorf("got=%+v ok=%v", got, ok)
	}
}

func TestGeoWithContext_NilInfoReturnsCtxUnchanged(t *testing.T) {
	base := context.Background()
	if got := geo.WithContext(base, nil); got != base {
		t.Error("nil info should return ctx unchanged")
	}
	if _, ok := geo.FromContext(base); ok {
		t.Error("base ctx should not have GeoInfo")
	}
}
