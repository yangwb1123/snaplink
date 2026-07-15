package middleware

import (
	"bytes"
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

// gzipResponseWriter wraps http.ResponseWriter to conditionally compress the
// body. Bodies under minCompressLen buffer instead of writing straight
// through: the compression decision determines which headers are honest
// (Content-Encoding: gzip vs none), and that decision can only be made once
// enough bytes are seen (or the handler finishes writing). Flushing a
// partial decision — as a naive per-Write bypass would — can announce gzip
// on the first WriteHeader call and then serve plaintext bytes for a short
// single-Write body, which any strict client fails to gunzip-decode.
type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	buf         bytes.Buffer
	statusCode  int
	wroteHeader bool // handler called WriteHeader (or implicitly via first Write)
	decided     bool // compression decided + real header flushed downstream
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	g.statusCode = code
	// Deliberately does not touch the underlying ResponseWriter yet — see
	// flush, which is the only place that decides (and sends) the real
	// header once compression is known one way or the other.
}

func (g *gzipResponseWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if g.decided {
		if g.gz != nil {
			return g.gz.Write(b)
		}
		return g.ResponseWriter.Write(b)
	}
	g.buf.Write(b) // bytes.Buffer.Write never errors
	if g.buf.Len() >= minCompressLen {
		if err := g.flush(true); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// flush makes the compress/don't-compress decision exactly once, sends the
// real status + headers consistent with that decision, and drains the
// buffered bytes accordingly. Called either from Write (body grew past the
// threshold — compress) or Close (body finished under the threshold —
// don't).
func (g *gzipResponseWriter) flush(compress bool) error {
	if g.decided {
		return nil
	}
	g.decided = true
	if compress {
		g.ResponseWriter.Header().Del("Content-Length")
		g.ResponseWriter.Header().Set("Content-Encoding", "gzip")
		g.ResponseWriter.Header().Del("ETag") // ETags change with compression
	}
	if g.statusCode == 0 {
		g.statusCode = http.StatusOK
	}
	g.ResponseWriter.WriteHeader(g.statusCode)
	buffered := g.buf.Bytes()
	if !compress {
		_, err := g.ResponseWriter.Write(buffered)
		return err
	}
	g.gz = gzip.NewWriter(g.ResponseWriter)
	_, err := g.gz.Write(buffered)
	return err
}

func (g *gzipResponseWriter) Close() error {
	if !g.decided {
		// Handler finished (or never wrote a byte) without crossing the
		// threshold: the honest header is "no compression".
		if err := g.flush(false); err != nil {
			return err
		}
	}
	if g.gz != nil {
		return g.gz.Close()
	}
	return nil
}

// compile-time check: gzipResponseWriter implements io.Closer.
var _ io.Closer = (*gzipResponseWriter)(nil)
