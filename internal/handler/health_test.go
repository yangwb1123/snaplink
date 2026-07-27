package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// TestHandleLivez locks the liveness probe: always 200 with the alive body and
// JSON content type.
func TestHandleLivez(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	HandleLivez(rec, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get(core.HeaderContentType); ct != core.ContentTypeJSON {
		t.Fatalf("content type = %q, want %q", ct, core.ContentTypeJSON)
	}
	if body := rec.Body.String(); body != `{"status":"alive"}` {
		t.Fatalf("body = %q", body)
	}
}

// echoOK is the downstream handler the middleware wraps; it reports whether it
// was reached and echoes any consumed body length so streaming-limit behavior
// can be asserted.
func newEchoHandler(reached *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		// Drain the body so a MaxBytesReader overflow surfaces here.
		_, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// TestBodyLimitMiddleware_PreCheck413 covers the Content-Length pre-check: an
// over-sized declared body is rejected with 413 BEFORE the downstream handler
// runs, and the body carries the payload_too_large error code.
func TestBodyLimitMiddleware_PreCheck413(t *testing.T) {
	t.Parallel()
	var reached bool
	mw := BodyLimitMiddleware(10, nil)
	h := mw(newEchoHandler(&reached))

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("0123456789ABCDEF"))
	req.ContentLength = 16 // exceeds the cap of 10
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if reached {
		t.Fatal("downstream handler must NOT run when Content-Length exceeds the cap")
	}
	if !strings.Contains(rec.Body.String(), core.ErrPayloadTooLarge) {
		t.Fatalf("body missing %q: %q", core.ErrPayloadTooLarge, rec.Body.String())
	}
	if ct := rec.Header().Get(core.HeaderContentType); ct != core.ContentTypeJSON {
		t.Fatalf("413 content type = %q, want JSON", ct)
	}
}

// TestBodyLimitMiddleware_UnderLimitPasses covers the happy path: a body within
// the cap reaches the downstream handler and returns 200.
func TestBodyLimitMiddleware_UnderLimitPasses(t *testing.T) {
	t.Parallel()
	var reached bool
	mw := BodyLimitMiddleware(100, nil)
	h := mw(newEchoHandler(&reached))

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("small"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("downstream handler should run for under-limit body")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestBodyLimitMiddleware_Unlimited covers the 0=unlimited default: no cap, no
// pre-check, no MaxBytesReader wrap — even a large declared body passes through.
func TestBodyLimitMiddleware_Unlimited(t *testing.T) {
	t.Parallel()
	var reached bool
	mw := BodyLimitMiddleware(0, nil)
	h := mw(newEchoHandler(&reached))

	req := httptest.NewRequest(http.MethodPost, "/anything", strings.NewReader("0123456789"))
	req.ContentLength = 1 << 20 // 1MiB declared
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("unlimited (0) must let any body through")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// TestBodyLimitMiddleware_LongestPrefixOverride locks the per-path override
// resolution: the longest matching prefix wins, an override of 0 means
// unlimited for that path even while a global cap is in effect, and unmatched
// paths fall back to the global default.
func TestBodyLimitMiddleware_LongestPrefixOverride(t *testing.T) {
	t.Parallel()
	byPath := map[string]int64{
		"/api":            5,    // short prefix, tight cap
		"/api/v1/scim":    1000, // longer prefix, generous cap
		"/api/v1/upload/": 0,    // unlimited escape hatch
	}
	mw := BodyLimitMiddleware(20, byPath)

	cases := []struct {
		name          string
		path          string
		contentLength int64
		wantStatus    int
		wantReached   bool
	}{
		// /api cap is 5; 6 bytes -> 413.
		{"short prefix tight cap rejects", "/api/login", 6, http.StatusRequestEntityTooLarge, false},
		// /api/v1/scim is the LONGER match (cap 1000); 6 bytes passes despite /api's 5.
		{"longest prefix wins over shorter", "/api/v1/scim/Users", 6, http.StatusOK, true},
		// /api/v1/upload/ override of 0 = unlimited even though /api would cap at 5.
		{"zero override is unlimited for path", "/api/v1/upload/big", 1 << 20, http.StatusOK, true},
		// No prefix match -> global default of 20; 21 bytes -> 413.
		{"unmatched path uses global default", "/token", 21, http.StatusRequestEntityTooLarge, false},
		// Unmatched path within global default passes.
		{"unmatched path under default passes", "/token", 10, http.StatusOK, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var reached bool
			h := mw(newEchoHandler(&reached))
			req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader("x"))
			req.ContentLength = c.contentLength
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if reached != c.wantReached {
				t.Fatalf("reached = %v, want %v", reached, c.wantReached)
			}
		})
	}
}

// TestBodyLimitMiddleware_StreamingGuard covers the chunked (no Content-Length)
// path: the pre-check can't fire, so the MaxBytesReader streaming guard must
// reject an over-sized body when the downstream handler reads it.
func TestBodyLimitMiddleware_StreamingGuard(t *testing.T) {
	t.Parallel()
	var reached bool
	mw := BodyLimitMiddleware(8, nil)
	h := mw(newEchoHandler(&reached))

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("way too many bytes here"))
	req.ContentLength = -1 // chunked: unknown length, pre-check is skipped
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !reached {
		t.Fatal("downstream handler runs for chunked bodies (pre-check skipped)")
	}
	// The echo handler maps a read error to 400; MaxBytesReader trips on read.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (MaxBytesReader overflow surfaced by handler read)", rec.Code)
	}
}
