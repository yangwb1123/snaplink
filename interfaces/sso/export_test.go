package sso

import (
	"context"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/signingkeys"
)

// AuditorSinkForTest exposes the recorder's current sink so a test can
// assert whether the CAEP transmitter tapped it (the sink becomes a
// MultiSink) or left it untouched (opt-in byte-identical proof).
func (s *Server) AuditorSinkForTest() audit.Sink {
	if s.auditor == nil {
		return nil
	}
	return s.auditor.Sink()
}

// HasCAEPTransmitterForTest reports whether a transmitter is wired.
func (s *Server) HasCAEPTransmitterForTest() bool { return s.caepTransmitter != nil }

// ApplySigningKeyEventForTest exposes the private applySigningKeyEvent to
// external (package sso_test) tests so they can drive the EventKeysRemoved /
// EventKeysUpserted reconcile path directly. The in-process memory registry
// never emits EventKeysRemoved on its own (real lease expiry arrives with the
// etcd backend), so this hook is the only way to exercise the drop path and
// the cross-replica refcount deterministically. It also lets a test set a
// stable replicaID without a registry wired.
//
// This lives in package sso (not sso_test) to reach the unexported method, but
// imports only signingkeys — never defaultimpl — so it introduces no import
// cycle.
func (s *Server) ApplySigningKeyEventForTest(evt signingkeys.Event) {
	s.applySigningKeyEvent(evt)
}

// SetReplicaIDForTest sets the replica id without wiring a registry, so a test
// can feed events through ApplySigningKeyEventForTest with a fixed local id.
func (s *Server) SetReplicaIDForTest(id string) { s.replicaID = id }

// SetSigningKeyAggBackoffBaseForTest shrinks the resubscribe backoff so a test
// can exercise the self-healing loop without waiting real seconds. Production
// leaves it 0 (the const). MUST be called before StartSigningKeyAggregation.
func (s *Server) SetSigningKeyAggBackoffBaseForTest(d time.Duration) {
	s.signingKeyAggBackoffBase = d
}

// SigningKeyAggDegradedForTest reads the degraded flag directly so a test can
// assert the state-machine transitions without depending on /readyz wiring.
func (s *Server) SigningKeyAggDegradedForTest() bool {
	return s.signingKeyAggDegraded.Load()
}

// --- Coordinated signing-key rotation cutover test seams ---

// ApplyCoordinatedKeyRotationForTest drives the bus-subscriber arm directly with
// a controllable ctx + Event, so a test exercises the receive side without
// standing up a real subscriber goroutine. Lives in package sso (not sso_test)
// to reach the unexported method; imports only cluster.
func (s *Server) ApplyCoordinatedKeyRotationForTest(ctx context.Context, evt cluster.Event) {
	s.applyCoordinatedKeyRotation(ctx, evt)
}

// SetCoordinatedRetireBoundsForTest shrinks the deferred-retire clamp floor +
// ceiling so a test's retire fires in milliseconds instead of the 1-minute
// production floor. Production leaves both 0 (the consts). The floor is still
// the fail-safe lower bound: a past/garbage deadline clamps UP to it, so even
// here the kid stays verifiable for at least `floor`.
func (s *Server) SetCoordinatedRetireBoundsForTest(floor, ceiling time.Duration) {
	s.coordinatedRetireMinDeferralOverride = floor
	s.coordinatedRetireMaxDeferralOverride = ceiling
}

// ClampRetireDeferralForTest exposes clampRetireDeferral so a test can assert
// on the computed deferral DURATION directly — without either shrinking the
// production bounds (which would defeat the point of testing them) or
// actually waiting out a real multi-day deferral. Used to prove an honest,
// realistic deadline (e.g. matching config.KeyRotationConfig's own
// documented 168h/7d GracePeriod example) is never clamped down below what
// the publisher actually carried, against the REAL production ceiling.
func (s *Server) ClampRetireDeferralForTest(now time.Time, deadlineRaw string) time.Duration {
	return s.clampRetireDeferral(now, deadlineRaw)
}

// PendingSigningRetireCountForTest reports how many deferred retires are
// currently armed, so a test can assert a clean shutdown / cancel drained them
// (no leaked timers).
func (s *Server) PendingSigningRetireCountForTest() int {
	s.pendingSigningRetireMu.Lock()
	defer s.pendingSigningRetireMu.Unlock()
	return len(s.pendingSigningRetires)
}

// BuildSigningKeyRotationEventForTest constructs the cluster.Event the publish
// side would emit, WITHOUT going through the bus, so the receive-side tests can
// feed a precisely-shaped (or deliberately-garbage) Event. retireDeadline is the
// raw MetaRetireDeadline string (a test passes a past/garbage value to exercise
// the fail-safe clamp). newJWKJSON, when non-empty, is the MetaNewJWK payload.
func BuildSigningKeyRotationEventForTest(oldKID, newKID, retireDeadline, newJWKJSON string) cluster.Event {
	payload := map[string]string{
		cluster.MetaOldKid:         oldKID,
		cluster.MetaNewKid:         newKID,
		cluster.MetaRetireDeadline: retireDeadline,
	}
	if newJWKJSON != "" {
		payload[cluster.MetaNewJWK] = newJWKJSON
	}
	return cluster.Event{Kind: cluster.KindSigningKeyRotation, Payload: payload}
}
