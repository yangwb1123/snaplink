package configaudit

import (
	"context"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// EventConfigDriftDetected is the audit.EventType emitted when a peer's
// broadcast config digest disagrees with this replica's own. audit.EventType
// is an open string type (custom values are allowed), so this constant lives
// next to the loop that emits it rather than in platform/audit — mirroring
// interfaces/sso's own invalidation-bus degraded/recovered event pair.
const EventConfigDriftDetected audit.EventType = "config_drift_detected"

// DriftDetector periodically broadcasts this replica's running-config
// digest on the cluster Bus and compares every PEER digest it receives
// against its own, so an operator can see "replica B's effective config
// diverged from mine" WITHOUT shipping full (possibly secret-bearing)
// config snapshots between replicas — only a sha256 digest crosses the
// wire (see Digest).
//
// Report-only by construction, matching AGENTS.md's fail-open cross-cutting
// convention for observability features: a mismatch NEVER blocks a
// request or changes any auth decision — it only emits an audit event and
// invokes onMismatch (typically a metric increment) so an operator notices
// a misconfigured or lagging replica.
type DriftDetector struct {
	bus        cluster.Bus
	replicaID  string
	interval   time.Duration
	digestFn   func(context.Context) (string, error)
	recorder   *audit.Recorder
	logger     spi.Logger
	onMismatch func(peerReplicaID, peerDigest, localDigest string)
}

// NewDriftDetector builds a detector. digestFn computes the CURRENT
// running-config digest on demand (typically Server.RunningConfigSnapshot
// composed with Digest). recorder and logger may be nil (best-effort: a nil
// recorder just skips the audit event). onMismatch may be nil; when set it
// is invoked synchronously on every detected mismatch.
func NewDriftDetector(
	bus cluster.Bus,
	replicaID string,
	interval time.Duration,
	digestFn func(context.Context) (string, error),
	recorder *audit.Recorder,
	logger spi.Logger,
	onMismatch func(peerReplicaID, peerDigest, localDigest string),
) *DriftDetector {
	return &DriftDetector{
		bus: bus, replicaID: replicaID, interval: interval, digestFn: digestFn,
		recorder: recorder, logger: logger, onMismatch: onMismatch,
	}
}

// Run starts the broadcast+compare loop and returns a channel that closes
// when ctx is cancelled. No-op (an already-closed channel, nil error) when
// the detector is nil, has no bus, or interval <= 0 — drift detection is
// opt-in and off by default (config/config_configaudit.go's DriftInterval
// defaults to 0), so an unconfigured deployment pays zero background-
// goroutine cost.
func (d *DriftDetector) Run(ctx context.Context) (<-chan struct{}, error) {
	done := make(chan struct{})
	if d == nil || d.bus == nil || d.interval <= 0 {
		close(done)
		return done, nil
	}
	events, err := d.bus.Subscribe(ctx)
	if err != nil {
		close(done)
		return done, err
	}
	go d.run(ctx, done, events)
	return done, nil
}

// run is the loop body: a single goroutine ticks the publish side and
// drains the subscription side. Unlike the safety-critical invalidation
// bus (server_invalidation.go), this feature is report-only, so a closed
// events channel simply ends the loop rather than triggering a
// self-healing resubscribe — a missed comparison window degrades to "no
// drift signal until the next successful subscribe", never to a wrong
// answer.
func (d *DriftDetector) run(ctx context.Context, done chan struct{}, events <-chan cluster.Event) {
	defer close(done)
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	// Compute an initial digest immediately so a peer Event arriving before
	// the first tick still has something to compare against, instead of a
	// silent no-op window at startup.
	localDigest := d.publish(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			localDigest = d.publish(ctx)
		case evt, ok := <-events:
			if !ok {
				return
			}
			d.comparePeer(evt, localDigest)
		}
	}
}

// publish computes and broadcasts the current running-config digest,
// returning it (empty on failure) so the caller can cache it for the next
// comparePeer call without recomputing per peer Event.
func (d *DriftDetector) publish(ctx context.Context) string {
	digest, err := d.digestFn(ctx)
	if err != nil {
		if d.logger != nil {
			d.logger.Error("configaudit: running-config digest failed", "error", err)
		}
		return ""
	}
	evt := cluster.Event{
		Kind:    cluster.KindConfigDigest,
		Key:     d.replicaID,
		Payload: map[string]string{cluster.MetaConfigDigest: digest},
	}
	if err := d.bus.Publish(ctx, evt); err != nil && d.logger != nil {
		d.logger.Error("configaudit: digest publish failed", "error", err)
	}
	return digest
}

// comparePeer checks one received Event against localDigest. Ignores
// non-digest kinds (the detector shares the Bus with every other
// subscriber), this replica's own echoed publish (evt.Key == d.replicaID
// — Publish fans out to every subscriber including one this same process
// opened), and an as-yet-unknown local digest (before the first publish).
func (d *DriftDetector) comparePeer(evt cluster.Event, localDigest string) {
	if evt.Kind != cluster.KindConfigDigest || evt.Key == d.replicaID || localDigest == "" {
		return
	}
	peerDigest := evt.Payload[cluster.MetaConfigDigest]
	if peerDigest == "" || peerDigest == localDigest {
		return
	}
	if d.recorder != nil {
		e := &audit.Event{Type: EventConfigDriftDetected, Outcome: audit.OutcomeFailure}
		audit.SetMeta(e, "peer_replica_id", evt.Key)
		d.recorder.Record(context.Background(), e)
	}
	if d.onMismatch != nil {
		d.onMismatch(evt.Key, peerDigest, localDigest)
	}
}
