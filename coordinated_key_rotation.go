package sso

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/metrics"
)

// Deadline-coordinated same-kid signing-key rotation cutover.
//
// THE PROBLEM. Signing-key rotation (defaultimpl.StartRotation) and the
// matching retirement (scheduleRetire) run on INDEPENDENT per-replica timers.
// The cluster.Bus has no rotation EventKind. During a rolling deploy a kid
// demoted-then-retired early on one replica leaves a token signed under it
// hitting a hard "unknown kid" 401 on a replica whose own retire timer already
// fired (or whose grace, in wall-clock terms, was shorter). The leaderless
// aggregation (signing_key_aggregation.go) answers "can B verify A's kid" but
// NOT "do all replicas retire the OLD kid at the same instant".
//
// THE FIX (opt-in, nil-bus byte-identical). When WithCoordinatedKeyRotation is
// armed AND an invalidation bus is wired, a local rotation PUBLISHES a
// cluster.KindSigningKeyRotation Event carrying the demoted kid, the new kid (+
// its public JWK), and a retire deadline (= now + the SAME RotationConfig
// GracePeriod). Every armed replica that RECEIVES it adopts the new kid
// verify-only at once and DEFERS the demoted kid's retirement to that deadline.
//
// THE FAIL-SAFE GATE. The deferral only ever WIDENS a replica's verify window.
// The per-replica local scheduleRetire still runs as the fallback (this code
// never cancels it). A dropped, garbage, or past Event can only DELAY a retire,
// never advance it: the carried deadline is clamped UP to a floor (>= the
// rotation default grace, so a short/past garbage value can't retire before the
// local fallback would) and DOWN to a ceiling (so a far-future value can't pin a
// key forever). Either way the kid stays verifiable AT LEAST as long as it would
// have without this feature — honoring AGENTS.md §2 "rotation serves
// outgoing+incoming keys". A bug here fails toward "old key stays verifiable
// longer" (safe), never "old key dropped early" (the 401 this exists to
// prevent).
//
// WALL CLOCK. The deadline is wall-clock-coordinated, so the same discipline
// AGENTS.md §2 mandates for session expiry applies: ops MUST slew, never step,
// the clock (chrony). A backward step only DELAYS a retire (the now-vs-deadline
// gap grows) — fail-safe — never advances one.

const (
	// coordinatedRetireMinDeferral is the floor the carried retire deadline is
	// clamped UP to (relative to local now). It is >= the rotation default grace
	// so a garbage-short or past deadline can NEVER schedule a retire earlier
	// than the local per-replica fallback would — the fail-safe "only widen"
	// guarantee. An honest deadline (publisher now + a sane grace) is far past
	// this floor and passes through untouched.
	coordinatedRetireMinDeferral = 1 * time.Minute

	// coordinatedRetireMaxDeferral is the ceiling the carried retire deadline is
	// clamped DOWN to (relative to local now). It bounds a malicious or buggy
	// far-future deadline so a peer can't pin a demoted key in every replica's
	// verify-set indefinitely (a resource leak, not a 401 — over-widening is the
	// SAFE direction, this just caps it). Generous: 24h dwarfs any sane grace,
	// so an honest deadline is never clamped down.
	coordinatedRetireMaxDeferral = 24 * time.Hour
)

// PublishSigningKeyRotation broadcasts a coordinated-rotation Event after a
// LOCAL signing-key rotation, so every armed peer defers the demoted kid's
// retirement to a shared deadline (= now + grace) and adopts the new kid
// verify-only at once. cmd calls it from RotationConfig.OnRotate (alongside the
// signing_key_rotated audit + discovery-cache bust + PublishSigningKeys), passing
// the SAME RotationConfig.GracePeriod so the deadline matches every replica's
// own local scheduleRetire target — DO NOT invent a separate window.
//
// Best-effort + fail-open: a publish error is logged and swallowed (the local
// rotation already succeeded; peers fall back to their own per-replica grace
// timer), mirroring InvalidateTenantSuspensionCache / InvalidateDiscoveryCache.
// No-op (and zero overhead) when WithCoordinatedKeyRotation isn't armed or no
// bus is wired — so cmd may call it unconditionally.
func (s *Server) PublishSigningKeyRotation(ctx context.Context, oldKID, newKID string, grace time.Duration) {
	if !s.coordinatedKeyRotation || s.invalidationBus == nil {
		return
	}
	if oldKID == "" || grace <= 0 {
		// Nothing to coordinate: no demoted kid to defer, or a non-retiring
		// rotation (grace<=0 keeps the old key forever locally). Skip — there is
		// no deadline to share.
		return
	}
	deadline := time.Now().Add(grace)
	payload := map[string]string{
		cluster.MetaOldKid:         oldKID,
		cluster.MetaNewKid:         newKID,
		cluster.MetaRetireDeadline: strconv.FormatInt(deadline.UnixNano(), 10),
	}
	// Carry the new key's public material so a receiver can adopt it verify-only
	// WITHOUT a fetch (the kid alone can't install a verify key). Best-effort: if
	// the issuer can't surface it, peers still get the old-kid deferral (the
	// fail-safe half) and the leaderless-aggregation path, if wired, propagates
	// the new key separately.
	if jwk, ok := s.jwkForKid(ctx, newKID); ok {
		if raw, err := json.Marshal(jwk); err == nil {
			payload[cluster.MetaNewJWK] = string(raw)
		}
	}
	evt := cluster.Event{Kind: cluster.KindSigningKeyRotation, Payload: payload}
	if err := s.invalidationBus.Publish(ctx, evt); err != nil {
		s.logger.Error("invalidation bus publish failed",
			"kind", string(evt.Kind), "old_kid", oldKID, "new_kid", newKID, "error", err)
	}
}

// jwkForKid returns the published JWK for kid from any wired JWKSProvider
// issuer (the rotating replica's union already contains the freshly-promoted
// key). ok=false when no issuer publishes that kid.
func (s *Server) jwkForKid(ctx context.Context, kid string) (core.JWK, bool) {
	if kid == "" {
		return core.JWK{}, false
	}
	for _, ti := range s.tokenIssuers {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(ctx)
		if err != nil {
			continue
		}
		for i := range jwks {
			if jwks[i].Kid == kid {
				return jwks[i], true
			}
		}
	}
	return core.JWK{}, false
}

// applyCoordinatedKeyRotation is the cluster.KindSigningKeyRotation arm of the
// bus subscriber (dispatched from applyInvalidation). It (1) adopts the new kid
// verify-only immediately, so this replica validates new-kid tokens at once,
// and (2) DEFERS the demoted kid's retirement to the carried (clamped) deadline.
//
// ctx is the subscriber's run context: every deferred-retire timer is bound to
// it, so a clean shutdown cancels all pending retires (no leaked goroutine).
//
// Fail-safe throughout: an Event this replica isn't armed for is dropped before
// reaching here (the default arm in applyInvalidation handles unknown kinds; the
// armed check is below for the same-process mixed-arming case). A garbage/past
// deadline is clamped to a floor (only ever DELAYS the retire) and a far-future
// one to a ceiling. The new-key adoption is best-effort and independent of the
// old-kid deferral.
func (s *Server) applyCoordinatedKeyRotation(ctx context.Context, evt cluster.Event) {
	if !s.coordinatedKeyRotation {
		// Not armed on this replica — ignore (byte-identical to a build without
		// the feature). The Event may still be on the bus for armed peers.
		return
	}

	oldKID := evt.Payload[cluster.MetaOldKid]
	newKID := evt.Payload[cluster.MetaNewKid]

	// (1) Adopt the new kid verify-only NOW, reusing the alg-confusion-safe
	// adoption path the leaderless aggregation uses (alg-match gate, per-kty
	// decode + on-curve / RSA>=2048 validation). Best-effort: a missing/
	// undecodable new JWK just skips this half — the deferral half still runs.
	// Treated as a peer announcement under a synthetic replica id so the
	// adopted kid is tracked and NOT clobbered by this replica's own local
	// rotation lifecycle.
	adopted := false
	if raw := evt.Payload[cluster.MetaNewJWK]; raw != "" && newKID != "" {
		var jwk core.JWK
		if err := json.Unmarshal([]byte(raw), &jwk); err == nil && jwk.Kid == newKID {
			s.ensureIssuerAlgs()
			if _, ok := s.adoptPeerKey(coordinatedRotationReplicaID, jwk); ok {
				adopted = true
			}
		}
	}

	// (2) Defer the demoted kid's retirement to the carried deadline.
	outcome := s.scheduleCoordinatedRetire(ctx, oldKID, evt.Payload[cluster.MetaRetireDeadline])
	if outcome == metrics.CutoverOutcomeNoop && adopted {
		// No retire to defer (old kid gone / never local) but the new key WAS
		// adopted — record that distinctly so a healthy adopt-only cutover isn't
		// mistaken for a garbage no-op.
		outcome = metrics.CutoverOutcomeAdoptedOnly
	}

	if s.metrics != nil {
		s.metrics.SigningKeyCutoverTotal.WithLabelValues(outcome).Inc()
	}
	audit.RecordSigningKeyRotationCoordinated(s.auditor, context.Background(), outcome)
}

// coordinatedRotationReplicaID is the synthetic peer id under which coordinated
// rotation adopts a new kid verify-only. Distinct from any real replicaID so the
// adoption-tracking refcount in signing_key_aggregation.go treats it as its own
// source (a real aggregation announcement for the same kid bumps the refcount,
// so neither path drops a kid the other still holds).
const coordinatedRotationReplicaID = "__coordinated_rotation__"

// pendingRetire is one armed deferred retire: the timer plus a stop channel so a
// ctx cancel (clean shutdown) or a superseding EXTEND can tear it down without a
// leaked goroutine. The single watcher goroutine selects on ctx.Done / fired /
// stopped.
type pendingRetire struct {
	timer   *time.Timer
	stopped chan struct{} // closed by an EXTEND/cancel that replaces this entry
}

// scheduleCoordinatedRetire arms (or extends) a ctx-cancellable deferred retire
// of oldKID at the clamped deadline. It returns the cutover outcome for the
// metric/audit. FAIL-SAFE: the deadline is clamped to [now+min, now+max] so a
// past/garbage value can never retire before the local fallback, and a pending
// timer for the same kid is only ever REPLACED by a LATER deadline (an earlier
// or equal one is a no-op — we never shorten a deferral we already granted).
func (s *Server) scheduleCoordinatedRetire(ctx context.Context, oldKID, deadlineRaw string) string {
	if oldKID == "" {
		return metrics.CutoverOutcomeNoop
	}
	// A demoted kid that isn't (and never was) in this replica's verify-set has
	// nothing to defer — retiring it is already a no-op. Skip cleanly so a
	// shared-key cluster (every replica holds the kid) defers while a replica
	// that never saw the kid doesn't arm a pointless timer.
	if !s.issuerHasKid(oldKID) {
		return metrics.CutoverOutcomeNoop
	}

	now := time.Now()
	deferral := s.clampRetireDeferral(now, deadlineRaw)
	target := now.Add(deferral)

	s.pendingSigningRetireMu.Lock()
	if s.pendingSigningRetires == nil {
		s.pendingSigningRetires = make(map[string]*pendingRetire)
	}
	outcome := metrics.CutoverOutcomeDeferred
	if existing, ok := s.pendingSigningRetires[oldKID]; ok {
		// A pending deferral already exists. We only ever EXTEND it — replacing
		// it with a LATER target. An earlier/equal target would shorten a window
		// we already promised, which is exactly the narrowing the fail-safe gate
		// forbids, so leave the longer one in place.
		if !target.After(s.pendingSigningRetireDeadlines[oldKID]) {
			s.pendingSigningRetireMu.Unlock()
			return metrics.CutoverOutcomeNoop
		}
		existing.timer.Stop()
		close(existing.stopped) // release the old watcher goroutine
		outcome = metrics.CutoverOutcomeExtended
	}

	pr := &pendingRetire{
		timer:   time.NewTimer(deferral),
		stopped: make(chan struct{}),
	}
	s.pendingSigningRetires[oldKID] = pr
	if s.pendingSigningRetireDeadlines == nil {
		s.pendingSigningRetireDeadlines = make(map[string]time.Time)
	}
	s.pendingSigningRetireDeadlines[oldKID] = target
	s.pendingSigningRetireMu.Unlock()

	// One watcher goroutine per armed timer, bound to the subscriber ctx so a
	// clean shutdown (or a superseding EXTEND, via stopped) tears it down — no
	// leaked goroutine, and a shutdown NEVER triggers a retire (fail-safe: a
	// torn-down server leaves the kid verifiable).
	go func() {
		defer func() { _ = recover() }() // a panic in RetireKey can't crash the process
		defer pr.timer.Stop()
		select {
		case <-ctx.Done():
			s.cancelPendingRetire(oldKID, pr)
		case <-pr.stopped:
			// Superseded by a later deferral (or cancelled) — exit; the replacing
			// entry owns the kid now.
		case <-pr.timer.C:
			s.runCoordinatedRetire(oldKID, pr)
		}
	}()

	return outcome
}

// runCoordinatedRetire performs the deferred drop of the demoted kid and clears
// the pending entry IFF this pendingRetire is still the live one for kid (a
// racing EXTEND may have replaced it). It tries BOTH issuer seams, because the
// demoted kid can be EITHER kind depending on the deployment:
//
//   - shared-KMS / same-kid: the kid is THIS replica's OWN demoted signing key
//     (in its rotation set) → RetireKey removes it. RetireKey refuses to retire
//     the ACTIVE key, so a kid re-promoted in the interim is correctly NOT
//     dropped (fail-safe — a wrongly-targeted retire is a no-op, never a drop of
//     a live signing key).
//   - per-replica keys + leaderless aggregation: the kid is a PEER's key this
//     replica holds VERIFY-ONLY (adopted) → DropVerifyKey removes it.
//
// Whichever seam owns the kid acts; the other is a harmless no-op. This is the
// agreed cluster-wide cutover instant, so dropping the demoted kid here is the
// intended terminal state. We do NOT touch the leaderless-aggregation refcount
// for the demoted kid: that bookkeeping is idempotent (its DropVerifyKey is a
// no-op once the kid is gone, and its <=0 refcount guard absorbs a stale entry),
// so a later aggregation reconcile for the same kid stays correct without this
// path reaching into the aggregation's lock.
func (s *Server) runCoordinatedRetire(kid string, pr *pendingRetire) {
	s.pendingSigningRetireMu.Lock()
	if s.pendingSigningRetires[kid] != pr {
		// Superseded between the timer firing and acquiring the lock — the live
		// entry owns the retire; do nothing.
		s.pendingSigningRetireMu.Unlock()
		return
	}
	delete(s.pendingSigningRetires, kid)
	delete(s.pendingSigningRetireDeadlines, kid)
	s.pendingSigningRetireMu.Unlock()

	for _, ti := range s.tokenIssuers {
		if r, ok := ti.(interface{ RetireKey(string) error }); ok {
			_ = r.RetireKey(kid)
		}
		if d, ok := ti.(interface{ DropVerifyKey(string) }); ok {
			d.DropVerifyKey(kid)
		}
	}
}

// cancelPendingRetire stops and forgets a pending deferred retire when the
// subscriber ctx is cancelled — but ONLY if pr is still the live entry (a
// racing EXTEND that replaced it already closed pr.stopped). The kid is left
// verifiable: a shutdown must never be the trigger that drops a key (fail-safe).
func (s *Server) cancelPendingRetire(kid string, pr *pendingRetire) {
	s.pendingSigningRetireMu.Lock()
	defer s.pendingSigningRetireMu.Unlock()
	if s.pendingSigningRetires[kid] != pr {
		return
	}
	pr.timer.Stop()
	delete(s.pendingSigningRetires, kid)
	delete(s.pendingSigningRetireDeadlines, kid)
}

// clampRetireDeferral converts the carried unix-nanosecond deadline string into
// a deferral DURATION from now, clamped to [min, max] (the production floor/
// ceiling, or the test overrides). An empty / unparsable / past deadline clamps
// to the floor (so the kid is still deferred — only ever DELAYED, never retired
// early). This is the fail-safe core: every code path returns a duration >= the
// floor, which is itself >= the rotation default grace in production, so a
// short/past garbage deadline can never retire before the local fallback would.
func (s *Server) clampRetireDeferral(now time.Time, deadlineRaw string) time.Duration {
	floor := s.retireMinDeferral()
	ceiling := s.retireMaxDeferral()
	deferral := floor
	if ns, err := strconv.ParseInt(deadlineRaw, 10, 64); err == nil {
		d := time.Unix(0, ns).Sub(now)
		if d > deferral {
			deferral = d
		}
	}
	if deferral > ceiling {
		deferral = ceiling
	}
	return deferral
}

func (s *Server) retireMinDeferral() time.Duration {
	if s.coordinatedRetireMinDeferralOverride > 0 {
		return s.coordinatedRetireMinDeferralOverride
	}
	return coordinatedRetireMinDeferral
}

func (s *Server) retireMaxDeferral() time.Duration {
	if s.coordinatedRetireMaxDeferralOverride > 0 {
		return s.coordinatedRetireMaxDeferralOverride
	}
	return coordinatedRetireMaxDeferral
}

// issuerHasKid reports whether any wired JWKSProvider issuer currently
// publishes kid (active or verify-only). Used to skip arming a deferral for a
// kid this replica never held.
func (s *Server) issuerHasKid(kid string) bool {
	if kid == "" {
		return false
	}
	_, ok := s.jwkForKid(context.Background(), kid)
	return ok
}
