package sso

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/oauth"
)

func (s *Server) InvalidateClientCache(clientID string) {
	if s.clientStoreCacheRef != nil {
		s.clientStoreCacheRef.evict(clientID)
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
	for {
		for evt := range events {
			s.applyInvalidation(ctx, evt)
		}
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

		next, err := s.invalidationBus.Subscribe(ctx)
		if err != nil {
			// Resubscribe failed (bus still down). Stay degraded and retry
			// after a longer backoff. A permanent-close error at shutdown is
			// benign — the next ctx check or backoff observes the cancel.
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("invalidation bus resubscribe failed, will retry", "attempt", attempt, "error", err)
			continue
		}
		// Recovered: clear degraded (gauge → 1, flag → false, recovered audit +
		// counter) and resume draining the fresh stream with a reset backoff.
		s.setInvalidationBusHealthy()
		events = next
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
		s.recordInvalidationBusEvent(eventInvalidationBusRecovered, audit.OutcomeSuccess, "")
	}
}

// recordInvalidationBusEvent emits a degraded/recovered audit event off the
// request path (the bus subscriber goroutine, no HandlerContext), building the
// Event directly over context.Background() — the same shape
// audit.RecordSigningKeyAggregationDegraded uses. nil-recorder-safe; reason,
// when non-empty, lands in Metadata via SetMeta (secret-free, fixed
// cardinality).
func (s *Server) recordInvalidationBusEvent(t audit.EventType, outcome audit.Outcome, reason string) {
	if s.auditor == nil {
		return
	}
	e := &audit.Event{Type: t, Outcome: outcome}
	if reason != "" {
		audit.SetMeta(e, "reason", reason)
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

// ErrCIBANotEnabled is returned by ResolveBackchannelAuthRequest when no
// CIBA store is wired (WithCIBA not configured). It is an SDK-level
// sentinel, not a wire error code.
var ErrCIBANotEnabled = errors.New("sso: CIBA is not enabled")

// cibaPingDeliveryTimeout bounds the detached ping goroutine spawned on
// resolution. The request that triggered the approval has already returned,
// so the goroutine runs on context.Background() with NO inherited deadline —
// without this bound a hanging/never-returning custom notifier would leak the
// goroutine forever. Deliberately set LONGER than the reference
// httpCIBAPingNotifier's own 5s HTTP client timeout so the transport's timeout
// fires first on the common path (yielding a clean error, not a context
// cancellation), while a custom notifier that ignores ctx still gets bounded.
const cibaPingDeliveryTimeout = 10 * time.Second

// ResolveBackchannelAuthRequest transitions a pending CIBA request to
// approved or denied and, in ping delivery mode, notifies the client.
// Operators call this from their device-confirmation callback instead of
// poking CIBAStore.SetStatus directly, so the ping fires automatically on
// resolution.
//
// The status transition is authoritative (the client's /token poll mints
// or refuses tokens off it). The ping is best-effort: when a
// CIBAPingNotifier is wired (WithCIBAPingNotifier) and the request
// carries a client_notification_token (ping mode), it fires asynchronously
// — a failed ping is logged, not returned, since the client can still
// poll. Poll-only requests (no notifier or no token) just transition.
//
// Returns ErrCIBANotEnabled if CIBA isn't wired, or the store's error for
// an unknown/expired (oauth.ErrCIBARequestNotFound) or already-resolved
// (oauth.ErrCIBARequestResolved) request.
func (s *Server) ResolveBackchannelAuthRequest(ctx context.Context, authReqID string, approved bool) error {
	if s.cibaStore == nil {
		return ErrCIBANotEnabled
	}
	// Read before transition so a racing /token poll that consumes +
	// deletes the entry can't strip the notification token from under us.
	req, err := s.cibaStore.Get(ctx, authReqID)
	if err != nil {
		return err
	}
	status := oauth.CIBADenied
	if approved {
		status = oauth.CIBAApproved
	}
	if err := s.cibaStore.SetStatus(ctx, authReqID, status); err != nil {
		return err
	}
	if s.cibaPingNotifier != nil && req.ClientNotificationToken != "" {
		clientID, token := req.ClientID, req.ClientNotificationToken
		// Fire-and-forget so the operator's resolution callback (and the
		// /token poll it races) never waits on the ping — the status
		// transition above is already authoritative. deliverCIBAPing supervises
		// the call (bounded timeout + recover + metric/audit on failure) so a
		// hanging webhook can't leak this goroutine and a panicking custom
		// notifier can't die silently.
		go s.deliverCIBAPing(clientID, authReqID, token)
	}
	return nil
}

// deliverCIBAPing supervises a single detached CIBA ping delivery. It is the
// body of the goroutine spawned by ResolveBackchannelAuthRequest, extracted so
// the timeout + recover + metric/audit wrapper is unit-testable in isolation.
//
// Hardening over the original bare `go n.Notify(context.Background(), ...)`:
//   - Bounded context: a hanging/never-returning notifier can no longer leak
//     this goroutine indefinitely (cibaPingDeliveryTimeout).
//   - recover(): a panicking custom notifier is contained here — it logs +
//     audits + counts an error instead of taking down the goroutine (and
//     potentially the process) with no trace.
//   - Observability: every outcome increments sso_ciba_ping_total{outcome};
//     failures (error return OR recovered panic) also emit a ciba_ping_failed
//     audit event so operators can see WHICH client's ping failed.
//
// The ping is best-effort by contract (the client can still poll), so a failure
// is logged + recorded, never surfaced — there is no caller to return to.
func (s *Server) deliverCIBAPing(clientID, authReqID, token string) {
	// recover() so a panic in a third-party notifier can't crash the goroutine
	// silently (or escalate to a process-wide crash on an unrecovered panic in
	// a bare goroutine). On recovery, treat it as a delivery failure.
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("panic: %v", r)
			s.logger.Error("ciba ping notification panicked", "auth_req_id", authReqID, "client_id", clientID, "panic", r)
			s.recordCIBAPingFailure(clientID, authReqID, reason)
		}
	}()

	// context.Background() is the correct PARENT here (the request that
	// triggered the approval has returned, so there is no live request ctx to
	// inherit — inheriting one would cancel the ping immediately). We ADD a
	// deadline so a notifier that blocks past the bound is unblocked and the
	// goroutine returns.
	ctx, cancel := context.WithTimeout(context.Background(), cibaPingDeliveryTimeout)
	defer cancel()

	if err := s.cibaPingNotifier.Notify(ctx, clientID, authReqID, token); err != nil {
		s.logger.Error("ciba ping notification failed", "auth_req_id", authReqID, "client_id", clientID, "error", err)
		s.recordCIBAPingFailure(clientID, authReqID, err.Error())
		return
	}
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("success").Inc()
	}
}

// recordCIBAPingFailure is the shared error tail for deliverCIBAPing: bump the
// error metric + emit the ciba_ping_failed audit event. Detached goroutine, so
// it audits over context.Background() via the background-context recorder helper
// (mirrors the signing-key aggregation degraded/recovered events).
func (s *Server) recordCIBAPingFailure(clientID, authReqID, reason string) {
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("error").Inc()
	}
	audit.RecordCIBAPingFailed(s.auditor, context.Background(), clientID, authReqID, reason)
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
			s.clientStoreCacheRef.evict(evt.Key)
		}
	case cluster.KindDiscoveryReload:
		s.invalidateDiscoveryCaches()
		s.InvalidateJWKSBodyCache()
	case cluster.KindAuthzPolicyChange:
		// evt.Key is the clientID whose role definitions changed; drop this
		// replica's cached bundle so the sidecar's next pull re-renders.
		s.invalidateAuthzPolicyBundleCacheLocal(evt.Key)
	case cluster.KindSigningKeyRotation:
		// A peer rotated its signing key: adopt the new kid verify-only now and
		// DEFER the demoted kid's retirement to the carried deadline (only ever
		// widening this replica's verify window — see coordinated_key_rotation.go).
		// No-op unless WithCoordinatedKeyRotation armed this replica.
		s.applyCoordinatedKeyRotation(ctx, evt)
		s.InvalidateJWKSBodyCache()
	case cluster.KindTokenRevoked:
		// A peer revoked an access token: ADD it to this replica's per-issuer
		// in-process deny-set via the LOCAL-only revoke path (which never
		// re-publishes — no broadcast loop). Purely additive + fail-open; no-op
		// unless WithCrossReplicaRevocation armed this replica. See
		// cross_replica_revocation.go.
		s.applyTokenRevocation(ctx, evt)
	default:
		// Unknown kind from a newer peer — ignore rather than error, so a
		// mixed-version cluster degrades gracefully during a rollout.
	}
}

// checkTenantNotSuspended is the post-validation gate. Returns nil
// when the token is allowed to proceed (no tenant binding, no store,
// store unreachable, or tenant active) and ErrTenantSuspended when
// the token's tenant has been suspended.
