package rs

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
)

func TestRequestHTUTrustedProxyGate(t *testing.T) {
	t.Parallel()
	tp, err := middleware.NewTrustedProxies([]string{"10.0.0.0/8"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{name: "trusted", remote: "10.0.0.2:443", want: "https://public.example/resource"},
		{name: "untrusted", remote: "203.0.113.8:443", want: "http://internal/resource"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			captured := ""
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				captured = requestHTU(r)
			})
			r := httptest.NewRequest(http.MethodGet, "http://internal/resource", nil)
			r.Host = "internal"
			r.RemoteAddr = tc.remote
			r.Header.Set("X-Forwarded-Proto", "https")
			r.Header.Set("X-Forwarded-Host", "public.example")
			tp.Middleware(next).ServeHTTP(httptest.NewRecorder(), r)
			if captured != tc.want {
				t.Fatalf("requestHTU = %q, want %q", captured, tc.want)
			}
		})
	}
}
