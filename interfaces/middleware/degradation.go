package middleware

import (
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/degradation"
	"github.com/yangwb1123/snaplink/shared/core"
)

// defaultDegradationRetryAfter is the Retry-After hint sent on a degraded 503
// when the caller supplies none. 30s is short enough that a client backs off
// briefly yet retries within a typical failover window.
const defaultDegradationRetryAfter = 30 * time.Second

// DegradationConfig wires the degraded-service enforcement gate.
type DegradationConfig struct {
	// Controller supplies the current [degradation.Mode]. Required — a nil
	// Controller makes the middleware a pass-through.
	Controller degradation.Controller

	// Policy decides, per mode, which method+path pairs remain permitted.
	Policy degradation.Policy

	// RetryAfter is the Retry-After header value sent on a refusal. <= 0 uses
	// defaultDegradationRetryAfter.
	RetryAfter time.Duration

	// OnReject, when set, is called for every refused request (for the
	// degraded-rejection metric). It runs BEFORE the response is written.
	OnReject func(mode degradation.Mode, r *http.Request)
}

// Degradation returns middleware that refuses requests the current
// degraded-service mode does not permit with 503 + Retry-After, letting every
// other request through untouched. Probe endpoints are permitted by the Policy
// in every mode, so liveness/readiness/metrics never trip the gate even if it
// is (unusually) mounted ahead of them.
//
// In ModeNormal (and when no Controller is wired) the gate is a pure
// pass-through — install it only when a manager is present so a build without
// the feature stays byte-identical.
func Degradation(cfg DegradationConfig) func(http.Handler) http.Handler {
	retry := cfg.RetryAfter
	if retry <= 0 {
		retry = defaultDegradationRetryAfter
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Controller == nil {
				next.ServeHTTP(w, r)
				return
			}
			mode := cfg.Controller.Mode()
			if cfg.Policy.Allow(mode, r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.OnReject != nil {
				cfg.OnReject(mode, r)
			}
			writeServiceDegraded(w, mode, retry)
		})
	}
}

// writeServiceDegraded emits the canonical degraded 503: a Retry-After hint
// (seconds, ceiling-rounded so a client never retries early) plus a minimal
// JSON body carrying the stable error code and the active mode so an SPA can
// branch on it.
func writeServiceDegraded(w http.ResponseWriter, mode degradation.Mode, retry time.Duration) {
	seconds := int(math.Ceil(retry.Seconds()))
	if seconds < 1 {
		seconds = 1
	}
	h := w.Header()
	h.Set(core.HeaderRetryAfter, strconv.Itoa(seconds))
	h.Set(core.HeaderContentType, core.ContentTypeJSON)
	w.WriteHeader(http.StatusServiceUnavailable)
	// mode is a fixed enum value (never caller-controlled free text), so the
	// hand-built JSON cannot be injected into.
	_, _ = w.Write([]byte(`{"` + core.KeyError + `":"` + core.ErrServiceDegraded + `","mode":"` + string(mode) + `"}`))
}
