package oidcsupport

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func TestRenderCheckSessionIframe(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check_session_iframe", nil)
	RenderCheckSessionIframe(core.NewContext(rec, req))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// The whole point of this endpoint is to BE framed by an arbitrary RP —
	// unlike every other rendered page in this package it must NOT carry
	// X-Frame-Options: DENY.
	if got := rec.Header().Get("X-Frame-Options"); got != "" {
		t.Fatalf("X-Frame-Options = %q, want unset (page must be embeddable)", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, CheckSessionCookieName) {
		t.Fatalf("body does not reference the cookie name %q", CheckSessionCookieName)
	}
	if !strings.Contains(body, "addEventListener") {
		t.Fatalf("body does not wire up the postMessage listener")
	}
}
