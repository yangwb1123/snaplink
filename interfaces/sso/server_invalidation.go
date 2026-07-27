package sso

import (
	"context"
	"errors"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/platform/metrics"
)

// InvalidateConnectionCache publishes a KindConnectionChange event to the
// cluster bus so every peer replica knows to reload its connection config
// after a connection was created, updated, or deleted via the admin API.
// Best-effort: a publish failure is logged but does not roll back the
// store write (mirrors InvalidateClientCache's error handling).
func (s *Server) InvalidateConnectionCache(connID string) {
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindConnectionChange, Key: connID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", connID, "error", err)
		}
	}
}

func (s *Server) InvalidateClientCache(clientID string) {
	if s.clientStoreCacheRef != nil {
		s.clientStoreCacheRef.Evict(clientID)
	}
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindClientChange, Key: clientID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", clientID, "error", err)
		}
	}
}

// Invalidation-bus resubscribe backoff bounds + the degraded-audit reason.
// Identical shape to the signing-key aggregation bounds (signing_key_aggregation.go):
// on a Subscribe-channel close while ctx is live the loop retries with an
// exponentially growing, deterministically-jittered, capped delay so a flapping
// bus backend doesn't hot-loop, and a fleet that all lost the bus at once
// de-synchronizes its retries without a randomness dependency.
const (
	invalidationBusBackoffInitial = 1 * time.Second
	invalidationBusBackoffMax     = 30 * time.Second

	// invalidationBusDegradedReason is the SetMeta reason on the one-per-
	// transition degraded audit event.
	invalidationBusDegradedReason = "subscribe_channel_closed"

	// invalidationBusReseedFailedReason is the SetMeta reason on the degraded
	// audit event emitted when a post-resubscribe re-seed fails (the bus is
	// back but converging the state missed during the outage did not succeed,
	// so the replica deliberately stays degraded).
	invalidationBusReseedFailedReason = "reseed_failed"

	// invalidationBusMetaReseeded is the SetMeta key marking the recovered
	// audit event as having converged missed state (cache flush + revocation
	// deny-set re-seed) BEFORE readiness went green.
	invalidationBusMetaReseeded = "re_seeded"
)

// Custom audit event types for the invalidation-bus self-heal transitions.
// audit.EventType is an open string type (custom values are allowed), so these
// live here next to the loop that emits them rather than in audit/ — mirroring
// the signing_key_aggregation_{degraded,recovered} pair semantically. Secret-
// free, fixed-cardinality, one per transition.
const (
	eventInvalidationBusDegraded  audit.EventType = "invalidation_bus_degraded"
	eventInvalidationBusRecovered audit.EventType = "invalidation_bus_recovered"
)

// StartInvalidationBus begins consuming cross-replica invalidation Events on
// this replica. Call it once with the process run context.
//
// Like [Server.StartSigningKeyAggregation] (whose loop this mirrors), the
// consumer SELF-HEALS: a single drain of the subscription is not enough,
// because the bus's Subscribe channel can close mid-life (etcd watch
// compaction / leader change / network blip — cluster/etcd returns on the first
// watch error and the bare `for range` goroutine would exit PERMANENTLY). That
// would SILENTLY stop all cross-replica coordination on this replica — tenant
// suspension, client-cache invalidation, coordinated key-rotation cutover, and
// cross-replica token revocation (a revoked token would keep validating here
// until its own exp) — while /readyz stayed green. So instead the loop marks
// itself DEGRADED (InvalidationBusReady → not-ready, sso_invalidation_bus_up →
// 0, one audit event + a reconnect-counter tick), backs off, and RESUBSCRIBES.
// A clean ctx-cancel (graceful shutdown) exits WITHOUT degrading. The returned
// channel closes ONLY when ctx is cancelled, so cmd coordinates shutdown the
// same way as the netpolicy Classifier + the signing-key aggregation loop.
//
// No-op when no bus is wired: returns an already-closed channel and a nil error
// so callers may invoke it unconditionally.
func (s *Server) StartInvalidationBus(ctx context.Context) (<-chan struct{}, error) {
	done := make(chan struct{})
	if s.invalidationBus == nil {
		close(done)
		return done, nil
	}
	// Synchronous first subscribe so a Subscribe error surfaces to the caller
	// at boot (matching the prior contract). A LATER channel close is the
	// self-heal path; an INITIAL failure is a wiring/transport fault.
	events, err := s.invalidationBus.Subscribe(ctx)
	if err != nil {
		close(done)
		return done, err
	}
	// Healthy from the first successful subscribe.
	s.setInvalidationBusHealthy()

	go s.runInvalidationBus(ctx, done, events)
	return done, nil
}

// runInvalidationBus is the self-healing consumer. It drains the current
// subscription, and on a channel close distinguishes a clean ctx-cancel (exit
// normally, NOT degraded) from a live-context bus drop (mark degraded, back
// off, resubscribe). Closes done exactly once, only when ctx is cancelled.
// Mirrors runSigningKeyAggregation precisely.
func (s *Server) runInvalidationBus(ctx context.Context, done chan struct{}, events <-chan cluster.Event) {
	defer close(done)
	attempt := 0
	// cancelSub releases the child context of the CURRENT resubscribed stream
	// once it is dead (see resubscribeAndReseed). The initial subscription from
	// StartInvalidationBus rides ctx directly, hence the no-op seed value.
	cancelSub := context.CancelFunc(func() {})
	for {
		for evt := range events {
			s.applyInvalidationSafe(ctx, evt)
		}
		cancelSub()
		// The channel closed. If ctx is done this is a clean shutdown — the
		// memory + etcd bus peers both close the stream BECAUSE ctx was
		// cancelled. Exit without marking degraded so a graceful drain never
		// trips /readyz or pages anyone.
		if ctx.Err() != nil {
			return
		}

		// A close with a live context is the silent-failure mode this loop
		// exists to defend against: mark degraded ONCE per transition (audit +
		// gauge + counter + flag), then back off and resubscribe.
		s.setInvalidationBusDegraded()

		attempt++
		if !sleepCtx(ctx, s.invalidationBusBackoff(attempt)) {
			return // ctx cancelled during backoff — clean exit.
		}

		// Resubscribe, then converge the state missed while degraded (cache
		// flush + revocation deny-set re-seed) BEFORE clearing degraded. Either
		// half failing keeps the replica degraded and retries after a longer
		// backoff (a shutdown-time failure is benign — the ctx check observes
		// the cancel).
		next, cancel, ok := s.resubscribeAndReseed(ctx, attempt)
		if !ok {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		// Recovered: clear degraded (gauge → 1, flag → false, recovered audit +
		// counter) and resume draining the fresh stream with a reset backoff.
		s.setInvalidationBusHealthy()
		events, cancelSub = next, cancel
		attempt = 0
	}
}

// setInvalidationBusDegraded flips the replica into the degraded state ONCE per
// transition: it no-ops if already degraded (so a flapping bus emits one audit
// event + one gauge write + one counter tick per outage, not per retry). Called
// only from the single subscriber goroutine, so the read-then-set is race-free
// w.r.t. itself; the flag is atomic only for the concurrent /readyz reader.
// Mirrors setSigningKeyAggDegraded.
func (s *Server) setInvalidationBusDegraded() {
	if s.invalidationBusDegraded.Swap(true) {
		return // already degraded — don't re-emit.
	}
	s.logger.Error("invalidation bus subscription closed while running; cross-replica invalidation stalled, resubscribing")
	if s.metrics != nil {
		s.metrics.InvalidationBusUp.Set(0)
		s.metrics.InvalidationBusReconnectsTotal.WithLabelValues(metrics.InvalidationBusReasonDegraded).Inc()
	}
	s.recordInvalidationBusEvent(eventInvalidationBusDegraded, audit.OutcomeFailure, invalidationBusDegradedReason)
}

// setInvalidationBusHealthy clears the degraded state. On the initial subscribe
// it just stamps the gauge to 1 (Swap returns false). On RECOVERY from a
// degraded state it additionally emits the recovered audit event + a
// reconnected counter tick. Symmetric with setInvalidationBusDegraded; one
// transition, one event. Mirrors setSigningKeyAggHealthy.
func (s *Server) setInvalidationBusHealthy() {
	wasDegraded := s.invalidationBusDegraded.Swap(false)
	if s.metrics != nil {
		s.metrics.InvalidationBusUp.Set(1)
	}
	if wasDegraded {
		s.logger.Info("invalidation bus subscription recovered; resumed applying cross-replica invalidations")
		if s.metrics != nil {
			s.metrics.InvalidationBusReconnectsTotal.WithLabelValues(metrics.InvalidationBusReasonReconnected).Inc()
		}
		// re_seeded=true is truthful by construction: recovery is only ever
		// reached through resubscribeAndReseed, whose re-seed succeeded.
		s.recordInvalidationBusEvent(eventInvalidationBusRecovered, audit.OutcomeSuccess, "",
			invalidationBusMetaReseeded, "true")
	}
}

// recordInvalidationBusEvent emits a degraded/recovered audit event off the
// request path (the bus subscriber goroutine, no HandlerContext), building the
// Event directly over context.Background() — the same shape
// audit.RecordSigningKeyAggregationDegraded uses. nil-recorder-safe; reason,
// when non-empty, lands in Metadata via SetMeta, as do any trailing key/value
// pairs (secret-free, fixed cardinality).
func (s *Server) recordInvalidationBusEvent(t audit.EventType, outcome audit.Outcome, reason string, metaKV ...string) {
	if s.auditor == nil {
		return
	}
	e := &audit.Event{Type: t, Outcome: outcome}
	if reason != "" {
		audit.SetMeta(e, "reason", reason)
	}
	for i := 0; i+1 < len(metaKV); i += 2 {
		audit.SetMeta(e, metaKV[i], metaKV[i+1])
	}
	s.auditor.Record(context.Background(), e)
}

// InvalidationBusReady reports whether this replica's cross-replica
// invalidation-bus subscription is healthy. It returns an error while the
// subscription is degraded (the bus stream closed and the loop is between
// resubscribe attempts) — at which point the replica is no longer applying
// cross-replica invalidations (a just-suspended tenant / edited client / revoked
// token is honored locally until its own TTL/exp). cmd wraps this into a /readyz
// ReadyCheck ONLY when a bus is wired; with no bus the loop never runs, the flag
// is always false, and no check is registered. Mirrors
// SigningKeyAggregationReady.
func (s *Server) InvalidationBusReady() error {
	if s.invalidationBusDegraded.Load() {
		return errors.New("cluster: invalidation bus subscription degraded (not applying cross-replica invalidations)")
	}
	return nil
}

// invalidationBusBackoff returns the resubscribe delay for the given 1-based
// attempt, identical in shape to signingKeyAggBackoff: exponential from the
// initial up to the cap, plus a deterministic per-attempt jitter (no rand). The
// base is the production const unless a test set invalidationBusBackoffBase.
func (s *Server) invalidationBusBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := invalidationBusBackoffInitial
	if s.invalidationBusBackoffBase > 0 {
		base = s.invalidationBusBackoffBase
	}
	max := invalidationBusBackoffMax
	if base > max {
		max = base
	}
	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	jitter := (d / 4) * time.Duration(attempt%5) / 5
	return d + jitter
}

// applyInvalidationSafe wraps applyInvalidation with a recover so a panic
// anywhere in the dispatch tree — a pluggable core.TokenIssuer's Revoke or
// AdoptVerifyKey, or any other injected store it reaches into — is contained
// to this ONE event instead of escaping runInvalidationBus's bare `for evt
// := range events` loop, which has no recover of its own. An unrecovered
// panic in ANY goroutine is process-fatal in Go: without this, one bad Bus
// event landing on a buggy custom TokenIssuer would crash the whole server.
// Mirrors dispatchBackchannelOne / applySigningKeyEventSafe's recover.
func (s *Server) applyInvalidationSafe(ctx context.Context, evt cluster.Event) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("invalidation bus: applying event panicked, event dropped",
				"kind", string(evt.Kind), "key", evt.Key, "panic", r)
		}
	}()
	s.applyInvalidation(ctx, evt)
}

// applyInvalidation clears the local cache a received Event targets. It
// MUST NOT re-publish — only the originating admin mutation publishes,
// so receivers clearing their cache here can't trigger a fan-out loop. ctx is
// the subscriber's run context, threaded so the coordinated-rotation arm can
// bind its deferred-retire timers to it (a clean shutdown cancels them); the
// cache-invalidation arms ignore it (they are synchronous).
func (s *Server) applyInvalidation(ctx context.Context, evt cluster.Event) {
	switch evt.Kind {
	case cluster.KindTenantSuspension:
		if s.tenantSuspensionCache != nil {
			s.tenantSuspensionCache.invalidate(evt.Key)
		}
	case cluster.KindTenantResidency:
		if s.tenantResidencyCache != nil {
			s.tenantResidencyCache.invalidate(evt.Key)
		}
	case cluster.KindClientChange:
		// evt.Key is the clientID whose metadata changed; drop this replica's
		// cached client snapshot so the next Get re-reads the authoritative
		// store. No-op when the opt-in client cache isn't wired.
		if s.clientStoreCacheRef != nil {
			s.clientStoreCacheRef.Evict(evt.Key)
		}
	case cluster.KindDiscoveryReload:
		s.invalidateDiscoveryCaches()
		s.InvalidateJWKSBodyCache()
	case cluster.KindAuthzPolicyChange:
		// evt.Key is the clientID whose role definitions changed; drop this
		// replica's cached bundle so the sidecar's next pull re-renders.
		s.invalidateAuthzPolicyBundleCacheLocal(evt.Key)
	case cluster.KindSigningKeyRotation:
		// A peer rotated its signing key: adopt the new kid verify-only now,
		// deferring the demoted kid's retirement (see coordinated_key_rotation.go).
		// No-op unless WithCoordinatedKeyRotation armed this replica.
		s.applyCoordinatedKeyRotation(ctx, evt)
		s.InvalidateJWKSBodyCache()
	case cluster.KindConnectionChange:
		// evt.Key is the connID whose config changed. No per-replica cache
		// exists yet to evict; arm kept explicit vs. the default (unknown
		// kind) branch for a mixed-version rollout.
	case cluster.KindSessionSuspended:
		s.applySessionSuspension(evt)
	case cluster.KindTokenRevoked:
		// A peer revoked an access token: ADD it to this replica's per-issuer
		// in-process deny-set via the LOCAL-only revoke path (which never
		// re-publishes — no broadcast loop). Purely additive + fail-open; no-op
		// unless WithCrossReplicaRevocation armed this replica. See
		// cross_replica_revocation.go.
		s.applyTokenRevocation(ctx, evt)
	case cluster.KindConfigDigest:
		// Handled by configaudit.DriftDetector's own bus subscription, not here.
	default:
		// Unknown kind from a newer peer — ignore rather than error, so a
		// mixed-version cluster degrades gracefully during a rollout.
	}
}

// applySessionSuspension handles KindSessionSuspended: evt.Key is the
// subjectID whose session(s) SuspendSessionExecutor just destroyed. Per
// KindSessionSuspended's doc (platform/cluster/bus.go), subscribers should
// evict any locally cached session entry -- but no per-replica session
// cache exists yet (every session check reads the authoritative
// SessionManager store directly, e.g. mesh_authz.go's meshCheckSession and
// introspectSessionActive), so there is nothing to invalidate today. This
// arm exists so a mixed-version cluster doesn't fall through to
// applyInvalidation's default (unknown kind) branch during a rollout; when
// a per-replica session cache is added, evict evt.Key here.
func (s *Server) applySessionSuspension(_ cluster.Event) {}

// StartConfigDriftDetection begins the opt-in cross-replica config-digest
// broadcast+compare loop (WithConfigDriftDetection). No-op (an
// already-closed channel, nil error) when no invalidation bus is wired or
// the interval is <= 0 — see configaudit.DriftDetector.Run. Call it once
// with the process run context, alongside StartInvalidationBus.
func (s *Server) StartConfigDriftDetection(ctx context.Context) (<-chan struct{}, error) {
	dd := configaudit.NewDriftDetector(
		s.invalidationBus, s.configReplicaID, s.configDriftInterval,
		s.runningConfigDigest, s.auditor, s.logger, s.onConfigDriftMismatch,
	)
	return dd.Run(ctx)
}

// runningConfigDigest composes RunningConfigSnapshot + configaudit.Digest
// into the single func(ctx) (string, error) DriftDetector needs.
func (s *Server) runningConfigDigest(ctx context.Context) (string, error) {
	snap, err := s.RunningConfigSnapshot(ctx)
	if err != nil {
		return "", err
	}
	return configaudit.Digest(snap)
}

// onConfigDriftMismatch is the DriftDetector metric hook: a peer's running-
// config digest disagreed with this replica's own. Report-only — never
// blocks or changes behavior (see configaudit.DriftDetector's doc).
func (s *Server) onConfigDriftMismatch(_, _, _ string) {
	if s.metrics != nil {
		s.metrics.ConfigDriftDetectedTotal.Inc()
	}
}

// checkTenantNotSuspended is the post-validation gate. Returns nil
// when the token is allowed to proceed (no tenant binding, no store,
// store unreachable, or tenant active) and ErrTenantSuspended when
// the token's tenant has been suspended.

// applyConfigAuditWiring, mountConfigAuditAPI, and the handleConfig* wrappers
// live in sso_wiring.go (relocated there to hold this file under the
// 500-line maintainability budget).
