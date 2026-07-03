// Package degradation implements the disaster-recovery degraded-service
// control plane: an atomically-swappable service Mode that a delivery-layer
// enforcement gate consults to shed non-essential request classes while a
// backing dependency (primary database, region, cluster peer) is impaired.
//
// The package is transport-agnostic on purpose — it holds NO HTTP-path
// constants. The delivery layer supplies the concrete endpoint sets via a
// [Policy]; this keeps the layering pointing DOWN (interfaces -> platform) and
// lets the enforcement gate be unit-tested against real paths without this
// package importing shared/core's path table.
package degradation

import "errors"

// Mode is the coarse availability posture the server currently serves under.
// Exactly one Mode is active at a time; transitions are driven by an operator
// (admin toggle) or an automated health loop that observes a heartbeat loss.
type Mode string

const (
	// ModeNormal serves every request — the default; when the server runs in
	// ModeNormal the enforcement gate is a pass-through (no request is refused).
	ModeNormal Mode = "normal"

	// ModeReadOnly refuses mutating writes while keeping reads and the
	// token-issuance plane alive. Used when the primary datastore has failed
	// over to a read replica: a write would error deep in a handler, so the gate
	// rejects it early with a clean 503 + Retry-After instead.
	ModeReadOnly Mode = "read_only"

	// ModeAuthOnly serves only the authentication + token-issuance plane (and the
	// static key/discovery reads a relying party needs to consume issued tokens);
	// admin, SCIM, and self-service surfaces are refused. Used to protect the
	// login path when a downstream management dependency is degraded.
	ModeAuthOnly Mode = "auth_only"

	// ModeLocalOnly refuses endpoints that depend on a reachable REMOTE system
	// (upstream-IdP home-realm discovery, federation fetch, inbound shared-signals
	// push); everything answerable from local state is still served. Used when
	// cross-boundary connectivity is impaired but the local replica is healthy.
	ModeLocalOnly Mode = "local_only"

	// ModeMaintenance refuses every non-probe request. Used for a planned
	// maintenance window or a full drain; liveness/readiness/metrics probes still
	// pass so orchestration can observe and route around the replica.
	ModeMaintenance Mode = "maintenance"
)

// ErrInvalidMode is returned by [Manager.SetMode] when asked to switch to a
// value outside the fixed enum, so a typo in an admin request can never wedge
// the server into an unknown posture.
var ErrInvalidMode = errors.New("degradation: invalid mode")

// Valid reports whether m is one of the defined modes.
func (m Mode) Valid() bool {
	switch m {
	case ModeNormal, ModeReadOnly, ModeAuthOnly, ModeLocalOnly, ModeMaintenance:
		return true
	}
	return false
}

// String returns the wire value of the mode.
func (m Mode) String() string { return string(m) }

// Controller is the read side the enforcement gate depends on: it observes the
// current mode without being able to change it. [Manager] implements it.
type Controller interface {
	Mode() Mode
}
