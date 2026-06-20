package metrics

import (
	"net/http"
	"time"
)

// Middleware wraps an http.Handler and records request count + latency
// on m. Call once at server-Handler construction; the wrapped handler
// goes everywhere the unwrapped one would have.
//
// `/metrics` itself MUST be served outside this middleware — a scrape
// hitting our metrics endpoint would self-inflate the counters. The
// sso package's Handler() builder takes care of that by routing
// /metrics directly to the promhttp handler.
func Middleware(m *Metrics) func(http.Handler) http.Handler {
	if m == nil {
		// Identity middleware when no metrics configured.
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			m.HTTPRequestsTotal.WithLabelValues(r.Method, statusClass(rec.status)).Inc()
			m.HTTPRequestDuration.WithLabelValues(r.Method).Observe(time.Since(start).Seconds())
		})
	}
}

// statusRecorder captures the response status code so the middleware
// can label by status_class. Defaults to 200 when the handler never
// calls WriteHeader (the net/http default).
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

// Write captures the implicit WriteHeader(200) that net/http issues
// when a handler calls Write without WriteHeader first.
func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// statusClass buckets HTTP status into the four standard families.
// Bounded cardinality (5 labels) regardless of how many distinct
// statuses the server emits.
func statusClass(code int) string {
	switch {
	case code < 200:
		return StatusClass1xx
	case code < 300:
		return StatusClass2xx
	case code < 400:
		return StatusClass3xx
	case code < 500:
		return StatusClass4xx
	default:
		return StatusClass5xx
	}
}
