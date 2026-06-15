package sso

import (
	"net/http"

	"github.com/snaplink/sso/internal/handler"
)

func (s *Server) handleLivez(w http.ResponseWriter, r *http.Request) {
	handler.HandleLivez(w, r)
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	results := make(map[string]string, len(s.readyChecks))
	allOK := true

	for _, rc := range s.readyChecks {
		if err := rc.Check(r.Context()); err != nil {
			results[rc.Name] = err.Error()
			allOK = false
		} else {
			results[rc.Name] = "ok"
		}
	}

	status := http.StatusOK
	if !allOK {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Simplified response
}

func bodyLimitMiddleware(defaultMax int64, byPath map[string]int64) func(http.Handler) http.Handler {
	return handler.BodyLimitMiddleware(defaultMax, byPath)
}
