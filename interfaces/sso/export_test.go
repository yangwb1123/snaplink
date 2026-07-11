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

// --- Invalidation-bus self-heal test seams (invalidation_bus_selfheal_test.go) ---
//
// Mirror the signing-key aggregation seams above: the self-heal tests live in
// package sso_test so they can wire the REAL defaultimpl issuers + stores
// (defaultimpl imports this package, so a package-sso test importing it would
// be an import cycle), and reach the unexported knobs through here.

// SetInvalidationBusBackoffBaseForTest shrinks the resubscribe backoff so a
// test can exercise the self-healing loop without waiting real seconds.
// Production leaves it 0 (the const). MUST be called before
// StartInvalidationBus.
func (s *Server) SetInvalidationBusBackoffBaseForTest(d time.Duration) {
	s.invalidationBusBackoffBase = d
}

// InvalidationBusDegradedForTest reads the degraded flag directly so a test
// can assert the state-machine transitions without depending on /readyz wiring.
func (s *Server) InvalidationBusDegradedForTest() bool {
	return s.invalidationBusDegraded.Load()
}

// PutTenantSuspensionForTest primes the tenant-suspension cache (requires
// WithTenantSuspensionCheck) so a test can observe applyInvalidation / the
// recovery flush evicting the entry.
func (s *Server) PutTenantSuspensionForTest(tenantID string, suspended bool) {
	s.tenantSuspensionCache.put(tenantID, suspended)
}

// TenantSuspensionFreshForTest reports whether the suspension cache still
// holds a fresh entry for tenantID (false once invalidated/flushed/expired).
func (s *Server) TenantSuspensionFreshForTest(tenantID string) bool {
	_, fresh := s.tenantSuspensionCache.get(tenantID)
	return fresh
}

// JWTExpUnsafeForTest exposes jwtExpUnsafe so a test can stamp a durable
// RevocationStore write with the token's real exp, as production revocation
// does.
func JWTExpUnsafeForTest(token string) int64 { return jwtExpUnsafe(token) }

// Exported aliases for the invalidation-bus audit vocabulary the self-heal
// tests assert on.
const (
	EventInvalidationBusDegradedForTest      = eventInvalidationBusDegraded
	EventInvalidationBusRecoveredForTest     = eventInvalidationBusRecovered
	InvalidationBusMetaReseededForTest       = invalidationBusMetaReseeded
	InvalidationBusReseedFailedReasonForTest = invalidationBusReseedFailedReason
)

// FlakyBusForTest re-exports the flaky in-memory bus fixture (defined in
// invalidation_bus_selfheal_test.go) to package sso_test, where the re-seed
// tests wire it alongside the REAL defaultimpl issuer + revocation store.
type FlakyBusForTest = flakyBus

// NewFlakyBusForTest constructs the fixture for package sso_test.
func NewFlakyBusForTest() *FlakyBusForTest { return newFlakyBus() }

// ForceCloseForTest closes the channel currently handed to the subscriber
// loop, simulating a watch death.
func (f *flakyBus) ForceCloseForTest() { f.forceClose() }

// SubscribeCountForTest reports how many times Subscribe has been called.
func (f *flakyBus) SubscribeCountForTest() int { return f.subscribeCount() }
