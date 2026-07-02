package connections

import "time"

// HealthStatus is the last-known reachability state of a connection's
// configured upstream IdP, as observed by the admin-triggered probe (see
// RunProbe / HandleAdminProbeConnection). Deliberately coarser than raw HTTP
// status codes so operators get a stable alert signal instead of chasing
// every upstream 5xx blip.
type HealthStatus string

const (
	// HealthUnknown is the zero value: no probe has ever run against this
	// connection. Distinct from HealthUnreachable so a freshly-created
	// connection doesn't read as "broken" before anyone has tested it.
	HealthUnknown HealthStatus = "unknown"
	// HealthHealthy: the last probe reached the upstream and got back a
	// well-formed discovery/metadata document.
	HealthHealthy HealthStatus = "healthy"
	// HealthDegraded: the upstream responded, but with an error status or a
	// malformed/incomplete document — reachable, but misconfigured or
	// unhealthy on its own end.
	HealthDegraded HealthStatus = "degraded"
	// HealthUnreachable: the probe could not complete the handshake at all
	// (DNS failure, connection refused, TLS error, timeout), or the
	// connection has no probeable upstream configured.
	HealthUnreachable HealthStatus = "unreachable"
)

// MaxHealthErrorLen bounds LastError so a verbose upstream failure (or a long
// wrapped-error chain) can never grow a stored health record unboundedly and
// the admin API response stays predictable in size. Probe errors are always
// transport/status text synthesized by the prober itself — NEVER the
// upstream's response body — so truncation never has secret material to cut
// through; it exists purely as a size bound.
const MaxHealthErrorLen = 500

// ConnectionHealth is the last recorded probe outcome for one connection.
// Kept as a record distinct from Connection (mirroring DomainVerification)
// because it is mutable operational STATE overwritten by every probe, not
// admin-edited configuration — Connection.Config changes deliberately don't
// reset it, so a health history survives an unrelated display-name edit.
type ConnectionHealth struct {
	ConnectionID  string
	Status        HealthStatus
	LastCheckedAt time.Time // zero if never probed
	LastSuccessAt time.Time // zero if never healthy
	LastError     string    // bounded (MaxHealthErrorLen); empty when Status == HealthHealthy
}

// DefaultConnectionHealth returns the HealthUnknown zero-value record for
// id — what Store.Health returns before any probe has ever run.
func DefaultConnectionHealth(id string) *ConnectionHealth {
	return &ConnectionHealth{ConnectionID: id, Status: HealthUnknown}
}

// TruncateHealthError bounds msg to MaxHealthErrorLen so a store write can
// never persist an unbounded probe-error string.
func TruncateHealthError(msg string) string {
	if len(msg) <= MaxHealthErrorLen {
		return msg
	}
	return msg[:MaxHealthErrorLen]
}
