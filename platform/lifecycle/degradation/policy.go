package degradation

import (
	"net/http"
	"strings"
)

// Policy declares, per mode, which requests remain permitted. The delivery
// layer populates it with the concrete endpoint paths (from shared/core's path
// table) so this package stays transport-agnostic and the decision stays a pure
// function that is trivial to unit-test against real paths.
//
// The zero Policy is safe: with empty sets, ModeReadOnly still permits reads,
// ModeAuthOnly refuses everything, ModeLocalOnly permits everything, and probe
// exemption simply does not apply.
type Policy struct {
	// ProbePaths always pass, in EVERY mode (exact match). Two classes belong
	// here: (1) the liveness / readiness / metrics probes, which orchestration
	// needs precisely when the server is degraded to observe and route around
	// the replica; and (2) the operator recovery lever (the DR mode toggle) —
	// were it shed like any other admin write, an operator could not lift a
	// maintenance / read_only / auth_only posture over HTTP.
	ProbePaths []string

	// ReadOnlyExempt lists paths whose MUTATING methods stay permitted in
	// ModeReadOnly (exact match) — the token-issuance / introspection plane,
	// which must keep working even when general writes are shed.
	ReadOnlyExempt []string

	// AuthOnlyAllow lists path PREFIXES permitted in ModeAuthOnly; every other
	// path is refused. The authentication + token-issuance plane plus the static
	// key / discovery reads a relying party needs to consume issued tokens.
	AuthOnlyAllow []string

	// LocalOnlyBlock lists path PREFIXES refused in ModeLocalOnly — the endpoints
	// that depend on a reachable REMOTE system. Everything else is served from
	// local state.
	LocalOnlyBlock []string
}

// Allow reports whether a request with the given HTTP method and path is
// permitted under mode. Probe paths always pass. An unrecognized mode fails
// OPEN (permits) — the gate must never harden the server into refusing traffic
// on a posture it does not understand.
func (p Policy) Allow(mode Mode, method, path string) bool {
	if exactAny(p.ProbePaths, path) {
		return true
	}
	switch mode {
	case ModeNormal, "":
		return true
	case ModeMaintenance:
		return false
	case ModeReadOnly:
		return isReadMethod(method) || exactAny(p.ReadOnlyExempt, path)
	case ModeAuthOnly:
		return prefixAny(p.AuthOnlyAllow, path)
	case ModeLocalOnly:
		return !prefixAny(p.LocalOnlyBlock, path)
	default:
		return true
	}
}

// isReadMethod reports whether method is a non-mutating HTTP method. Only these
// are auto-permitted in read_only; every other method is treated as a mutation.
func isReadMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

func exactAny(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func prefixAny(list []string, s string) bool {
	for _, v := range list {
		if v != "" && strings.HasPrefix(s, v) {
			return true
		}
	}
	return false
}
