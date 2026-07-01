package middleware

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
)

// minCompressLen is the minimum response body size for compression.
// Responses smaller than this are not worth compressing.
const minCompressLen = 1024

// Compress returns an http.Handler middleware that compresses responses
// with gzip when the client supports it and the response is large enough.
// Inspired by the stdlib's httpgzip pattern.
func Compress(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		// Use a wrapper that compresses on Write calls.
		gzw := &gzipResponseWriter{ResponseWriter: w}
		defer gzw.Close()
		next.ServeHTTP(gzw, r)
	})
}

// gzipResponseWriter wraps http.ResponseWriter to compress the body.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz         *gzip.Writer
	wroteHeader bool
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	g.ResponseWriter.Header().Del("Content-Length")
	g.ResponseWriter.Header().Set("Content-Encoding", "gzip")
	g.ResponseWriter.Header().Del("ETag") // ETags change with compression
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if len(b) < minCompressLen && g.gz == nil {
		// Small body: bypass compression.
		return g.ResponseWriter.Write(b)
	}
	if g.gz == nil {
		g.gz = gzip.NewWriter(g.ResponseWriter)
	}
	return g.gz.Write(b)
}

func (g *gzipResponseWriter) Close() error {
	if g.gz != nil {
		return g.gz.Close()
	}
	return nil
}

// compile-time check: gzipResponseWriter implements io.Closer.
var _ io.Closer = (*gzipResponseWriter)(nil)
