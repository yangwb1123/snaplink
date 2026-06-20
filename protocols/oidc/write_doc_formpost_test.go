package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

func TestWriteDoc_ServesBodyWithHeaders(t *testing.T) {
	body := []byte(`{"issuer":"https://as.example"}`)
	entry := oidc.BuildDocEntry(body, time.Hour)

	ctx, rec := newCtx(http.MethodGet, "/.well-known/openid-configuration")
	oidc.WriteDoc(ctx, entry, 30*time.Second)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != string(body) {
		t.Errorf("body = %q, want %q", got, body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != core.ContentTypeJSON {
		t.Errorf("Content-Type = %q, want %q", ct, core.ContentTypeJSON)
	}
	if rec.Header().Get("ETag") != entry.ETag {
		t.Errorf("ETag = %q, want %q", rec.Header().Get("ETag"), entry.ETag)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=30") {
		t.Errorf("Cache-Control = %q, want max-age=30", cc)
	}
}

func TestWriteDoc_IfNoneMatch304(t *testing.T) {
	entry := oidc.BuildDocEntry([]byte(`{"a":1}`), time.Hour)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("If-None-Match", entry.ETag)
	oidc.WriteDoc(core.NewContext(rec, req), entry, 5*time.Second)

	if rec.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("304 must have empty body, got %d bytes", rec.Body.Len())
	}
	// Validators are still emitted on a 304 so the client can keep caching.
	if rec.Header().Get("ETag") != entry.ETag {
		t.Error("ETag must still be set on 304")
	}
}

func TestWriteDoc_NonMatchingETagServesBody(t *testing.T) {
	entry := oidc.BuildDocEntry([]byte(`{"a":1}`), time.Hour)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	req.Header.Set("If-None-Match", `"different"`)
	oidc.WriteDoc(core.NewContext(rec, req), entry, 5*time.Second)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for non-matching ETag", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("non-matching ETag must serve the body")
	}
}

func TestWriteDoc_ClampsSubSecondTTL(t *testing.T) {
	entry := oidc.BuildDocEntry([]byte(`{}`), time.Hour)
	ctx, rec := newCtx(http.MethodGet, "/.well-known/openid-configuration")
	// A sub-second cacheTTL must be clamped so Cache-Control never carries
	// max-age=0 (which would defeat downstream caching entirely).
	oidc.WriteDoc(ctx, entry, 500*time.Millisecond)
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=1") {
		t.Errorf("Cache-Control = %q, want max-age clamped to 1", cc)
	}
}

func TestRenderFormPostResponse_AutoSubmitForm(t *testing.T) {
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.RenderFormPostResponse(ctx, "https://rp.example/cb", "the-code", "the-state", "https://as.example")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`action="https://rp.example/cb"`,
		`name="code" value="the-code"`,
		`name="state" value="the-state"`,
		`name="iss" value="https://as.example"`,
		"document.forms[0].submit()",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

func TestRenderFormPostResponse_SecurityHeaders(t *testing.T) {
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.RenderFormPostResponse(ctx, "https://rp.example/cb", "c", "", "iss")

	if xfo := rec.Header().Get("X-Frame-Options"); xfo != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", xfo)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if rp := rec.Header().Get("Referrer-Policy"); rp != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", rp)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

func TestRenderFormPostResponse_OmitsEmptyState(t *testing.T) {
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	oidc.RenderFormPostResponse(ctx, "https://rp.example/cb", "c", "", "iss")
	if strings.Contains(rec.Body.String(), `name="state"`) {
		t.Error("empty state must be omitted from the form")
	}
}

func TestRenderFormPostResponse_EscapesUntrustedValues(t *testing.T) {
	ctx, rec := newCtx(http.MethodGet, "/auth/login")
	// A code that tries to break out of the value attribute must be
	// contextually escaped by html/template, not rendered verbatim.
	oidc.RenderFormPostResponse(ctx, "https://rp.example/cb", `"><script>x</script>`, "", "iss")
	body := rec.Body.String()
	if strings.Contains(body, "<script>x</script>") {
		t.Errorf("unescaped script payload leaked into HTML:\n%s", body)
	}
}
