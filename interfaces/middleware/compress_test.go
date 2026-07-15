package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCompress_SmallBody_NeverAnnouncesGzip is the regression test for the
// bug where WriteHeader unconditionally set Content-Encoding: gzip before
// the body size (and therefore the real compression decision) was known.
// A single Write under minCompressLen bypassed the gzip.Writer entirely, so
// the client received a header promising gzip alongside a plaintext body —
// any strict decoder fails to gunzip it.
func TestCompress_SmallBody_NeverAnnouncesGzip(t *testing.T) {
	const body = "short body"
	h := Compress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Fatalf("Content-Encoding = %q, want unset for an uncompressed body", ce)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("body = %q, want plaintext %q", got, body)
	}
}

// TestCompress_LargeBody_ActuallyGzips confirms the mirror image: once the
// body crosses minCompressLen, the response IS gzip-encoded and decodes back
// to the original bytes — the header is never a lie in either direction.
func TestCompress_LargeBody_ActuallyGzips(t *testing.T) {
	body := strings.Repeat("x", minCompressLen+1)
	h := Compress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want %q", ce, "gzip")
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("body did not decode as gzip: %v", err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if string(got) != body {
		t.Fatalf("decompressed body mismatch (len got=%d want=%d)", len(got), len(body))
	}
}

// TestCompress_MultipleSmallWritesCrossingThreshold_StillCompresses proves
// the buffering decision is made on ACCUMULATED size, not per-Write — a
// handler that dribbles bytes across several small Write calls whose sum
// exceeds minCompressLen must still get an honest gzip response.
func TestCompress_MultipleSmallWritesCrossingThreshold_StillCompresses(t *testing.T) {
	chunk := strings.Repeat("y", minCompressLen/2)
	h := Compress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chunk))
		_, _ = w.Write([]byte(chunk))
		_, _ = w.Write([]byte(chunk))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want %q", ce, "gzip")
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("body did not decode as gzip: %v", err)
	}
	defer zr.Close()
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	if want := chunk + chunk + chunk; string(got) != want {
		t.Fatalf("decompressed body mismatch (len got=%d want=%d)", len(got), len(want))
	}
}

// TestCompress_NoAcceptEncoding_PassesThroughUnwrapped confirms a client
// that never advertises gzip support gets the raw ResponseWriter untouched
// (no Content-Encoding header, no buffering indirection at all).
func TestCompress_NoAcceptEncoding_PassesThroughUnwrapped(t *testing.T) {
	const body = "plain"
	h := Compress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Fatalf("Content-Encoding = %q, want unset", ce)
	}
	if got := rec.Body.String(); got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

// TestCompress_EmptyBody_NoWriteCall covers a handler that only calls
// WriteHeader (e.g. 204/304) and never Write — Close must still flush an
// honest (uncompressed) header exactly once instead of hanging the decision.
func TestCompress_EmptyBody_NoWriteCall(t *testing.T) {
	h := Compress(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if ce := rec.Header().Get("Content-Encoding"); ce != "" {
		t.Fatalf("Content-Encoding = %q, want unset", ce)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
}
