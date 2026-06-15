package handler

import (
	"net/http"
)

// HandleLivez serves GET /livez — always 200 with {"status":"ok"}.
func HandleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// BodyLimitMiddleware returns an HTTP middleware that limits request body size.
func BodyLimitMiddleware(defaultMax int64, byPath map[string]int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			max := defaultMax
			for prefix, limit := range byPath {
				if len(r.URL.Path) >= len(prefix) && r.URL.Path[:len(prefix)] == prefix {
					max = limit
					break
				}
			}
			if max > 0 {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}
