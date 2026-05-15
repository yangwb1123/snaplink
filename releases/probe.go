package releases

import "context"

// HealthProbe checks if a just-pinned release is actually healthy.
// Used by Registry.Pin to gate auto-rollback when a forward Pin
// hands traffic to a release that fails to come up.
//
// Implementations live alongside in releases/probe/*. An http probe
// ships in the box; operators can write their own (gRPC health check,
// queue depth, custom CI signal) by implementing this single method.
//
// Probe is called on a polling cadence (Registry.ProbePolls /
// ProbeBackoff). Returning nil at any attempt satisfies the gate;
// returning a non-nil error after the final attempt triggers
// auto-rollback to the previous release (when one exists).
type HealthProbe interface {
	Probe(ctx context.Context, target *Release) error
}
