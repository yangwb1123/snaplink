package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/core"
)

func TestTokenNoStoreHeaders(t *testing.T) {
	t.Parallel()

	r, _ := http.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	ctx := core.NewContext(w, r)
	TokenNoStoreHeaders(ctx)

	h := w.Header()
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", h.Get("Cache-Control"))
	}
	if h.Get("Pragma") != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", h.Get("Pragma"))
	}
}

func TestBaseURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawURL  string
		headers map[string]string
		want    string
	}{
		{name: "simple", rawURL: "http://example.com/path",
			headers: map[string]string{"X-Forwarded-Proto": "https"}, want: "https://example.com"},
		{name: "with port", rawURL: "http://example.com:8443/path", want: "http://example.com:8443"},
		{name: "with x-forwarded-proto", rawURL: "http://example.com/path",
			headers: map[string]string{"X-Forwarded-Proto": "https"}, want: "https://example.com"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest("GET", tc.rawURL, nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			got := BaseURL(r)
			if got != tc.want {
				t.Errorf("BaseURL(%q) = %q, want %q", tc.rawURL, got, tc.want)
			}
		})
	}
}

func TestRealClientIP(t *testing.T) {
	t.Parallel()

	r, _ := http.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:1234"
	// Without context value, returns RemoteAddr without port
	if got := RealClientIP(r); got != "192.168.1.1" {
		t.Errorf("RealClientIP() without context = %q, want 192.168.1.1", got)
	}

	// With context value (set by TrustedProxies middleware)
	ctx := context.WithValue(r.Context(), realClientIPKey{}, "10.0.0.1")
	r = r.WithContext(ctx)
	if got := RealClientIP(r); got != "10.0.0.1" {
		t.Errorf("RealClientIP() with context = %q, want 10.0.0.1", got)
	}
}

func TestStripPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:443", "::1"},
		{"192.168.1.1", "192.168.1.1"},
		{"", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.addr, func(t *testing.T) {
			t.Parallel()
			got := stripPort(tc.addr)
			if got != tc.want {
				t.Errorf("stripPort(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

func TestNewRequestID(t *testing.T) {
	t.Parallel()

	id1 := newRequestID()
	id2 := newRequestID()
	if id1 == "" {
		t.Error("newRequestID() returned empty")
	}
	if id1 == id2 {
		t.Error("newRequestID() should return unique values")
	}
	if len(id1) < 8 {
		t.Errorf("newRequestID() too short: %q", id1)
	}
}

func TestSubjectFromContext(t *testing.T) {
	t.Parallel()

	// No subject in context
	r, _ := http.NewRequest("GET", "/", nil)
	if got := SubjectFromContext(r); got != "" {
		t.Errorf("SubjectFromContext() without subject = %q, want empty", got)
	}

	// With subject
	ctx := WithSubject(r.Context(), "user123")
	r = r.WithContext(ctx)
	if got := SubjectFromContext(r); got != "user123" {
		t.Errorf("SubjectFromContext() = %q, want user123", got)
	}
}
