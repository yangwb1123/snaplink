package sso_test

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/cluster"
	clustermemory "github.com/yangwb1123/snaplink/platform/cluster/memory"
	"github.com/yangwb1123/snaplink/shared/core"
)

// newCoordServer builds a minimal Server with one Ed25519 JWT issuer, the given
// bus, and coordinated rotation armed (unless arm=false). The returned issuer is
// the same instance wired into the Server, so a test can RotateKey it and watch
// the Server publish / the issuer's verify-set change.
func newCoordServer(t *testing.T, bus cluster.Bus, arm bool) (*sso.Server, *defaultimpl.Ed25519JWTIssuer) {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(10*time.Minute),
	)
	opts := []sso.Option{
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithDefaultTokenStrategy(sso.TokenStrategyJWT),
		sso.WithInvalidationBus(bus),
	}
	if arm {
		opts = append(opts, sso.WithCoordinatedKeyRotation())
	}
	return sso.NewServer(opts...), iss
}

// issueUnderKid mints a token from iss (signed by its current active kid).
func issueUnderKid(t *testing.T, iss *defaultimpl.Ed25519JWTIssuer) string {
	t.Helper()
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "u", ClientID: "c"}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok.AccessToken
}

func validates(iss *defaultimpl.Ed25519JWTIssuer, token string) bool {
	_, err := iss.Validate(context.Background(), token)
	return err == nil
}

// TestCoordinatedRotation_CutoverAcrossReplicas is the end-to-end property: two
// in-process "replicas" share a memory bus. Replica A rotates its signing key
// and publishes the coordinated-rotation Event; replica B (a) adopts A's new kid
// verify-only IMMEDIATELY, (b) keeps A's OLD kid verifiable until the deadline,
// (c) retires it AT/AFTER the deadline. B can verify an old-kid token before the
// deadline and the kid is gone after.
func TestCoordinatedRotation_CutoverAcrossReplicas(t *testing.T) {
	t.Parallel()
	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srvA, issA := newCoordServer(t, bus, true)

	// Replica B is a SEPARATE Server whose issuer initially knows A's old kid
	// (it has adopted it verify-only via aggregation — we simulate that by
	// adopting A's old public key directly so B can verify A's old-kid tokens).
	srvB, issB := newCoordServer(t, bus, true)
	// Tiny clamp FLOOR so the carried deadline (now+grace) — not the floor —
	// governs the retire timing; generous ceiling so the deadline is never
	// clamped down.
	srvB.SetCoordinatedRetireBoundsForTest(5*time.Millisecond, 10*time.Second)

	// B adopts A's OLD signing key verify-only (the pre-rotation steady state a
	// real cluster reaches via the leaderless aggregation).
	oldKID := issA.KeyID()
	if err := issB.AdoptVerifyKey(oldKID, issA.PublicKey()); err != nil {
		t.Fatalf("seed B with A's old key: %v", err)
	}

	// A token A signed under the OLD kid — B can verify it now.
	oldTok := issueUnderKid(t, issA)
	if !validates(issB, oldTok) {
		t.Fatal("precondition: B should verify A's old-kid token before rotation")
	}

	// Start B's bus subscriber so it RECEIVES A's published Event.
	doneB, err := srvB.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start B bus: %v", err)
	}
	defer func() { cancel(); <-doneB }()

	// A rotates: a new kid becomes active. A publishes the coordinated Event
	// with a SHORT deadline (so the test doesn't wait a real minute — B's clamp
	// floor governs the actual retire timing anyway).
	newKID, err := issA.RotateKey(nil)
	if err != nil {
		t.Fatalf("A RotateKey: %v", err)
	}
	// A token A signs under the NEW kid — B cannot verify it yet.
	newTok := issueUnderKid(t, issA)
	if validates(issB, newTok) {
		t.Fatal("precondition: B should NOT verify A's new-kid token before adoption")
	}

	// A publishes through the REAL bus with a short grace, so the carried
	// deadline is now+grace (~300ms) and B retires the old kid around then. The
	// new key's JWK is fetched from A's wired issuer by the publish side. 300ms
	// leaves ample margin: adoption (a) settles in a few ms, so (b) runs well
	// before the deadline even under -race load.
	grace := 300 * time.Millisecond
	srvA.PublishSigningKeyRotation(ctx, oldKID, newKID, grace)

	// (a) B adopts the new kid verify-only IMMEDIATELY — its next validate of a
	// new-kid token succeeds within a short settle window.
	if !waitUntil(2*time.Second, func() bool { return validates(issB, newTok) }) {
		t.Fatal("B did not adopt A's new kid verify-only after the coordinated Event")
	}

	// (b) BEFORE the deadline/clamp-floor elapses, B STILL verifies the old-kid
	// token (the verify window was DEFERRED, not narrowed).
	if !validates(issB, oldTok) {
		t.Fatal("B dropped A's old kid too early — fail-safe violated")
	}

	// (c) AT/AFTER the deadline (clamped to B's 60ms floor) B retires the old
	// kid: the old-kid token no longer validates.
	if !waitUntil(2*time.Second, func() bool { return !validates(issB, oldTok) }) {
		t.Fatal("B never retired A's old kid after the coordinated deadline")
	}
	// And the new kid still validates — the new-signer side stuck.
	if !validates(issB, newTok) {
		t.Fatal("B lost the new kid after the old-kid retire")
	}
}

// TestCoordinatedRotation_FailSafe_GarbageDeadlineDoesNotRetireEarly locks the
// fail-safe gate: a PAST (garbage) retire_deadline must NOT cause B to drop the
// old kid before the clamp floor — the deferral is clamped UP to the floor, so
// the kid stays verifiable. A dropped/garbage event only ever DELAYS the retire.
func TestCoordinatedRotation_FailSafe_GarbageDeadlineDoesNotRetireEarly(t *testing.T) {
	t.Parallel()
	srvB, issB := newCoordServer(t, clustermemory.New(), true)
	// A generous floor so we can observe "still verifiable" for a real interval
	// before the clamped retire eventually fires.
	srvB.SetCoordinatedRetireBoundsForTest(300*time.Millisecond, time.Second)

	// Seed B with a peer "old" key it can verify.
	peer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("peer"))
	oldKID := peer.KeyID()
	if err := issB.AdoptVerifyKey(oldKID, peer.PublicKey()); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	oldTok := issueUnderKid(t, peer)
	if !validates(issB, oldTok) {
		t.Fatal("precondition: B verifies the peer old-kid token")
	}

	// A deliberately PAST deadline (an hour ago) — a buggy/malicious publisher.
	pastDeadline := strconv.FormatInt(time.Now().Add(-time.Hour).UnixNano(), 10)
	evt := sso.BuildSigningKeyRotationEventForTest(oldKID, "new-kid", pastDeadline, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvB.ApplyCoordinatedKeyRotationForTest(ctx, evt)

	// IMMEDIATELY after applying the past-deadline event, the old kid MUST still
	// be verifiable (clamped to the 300ms floor — NOT retired in the past).
	if !validates(issB, oldTok) {
		t.Fatal("FAIL-SAFE VIOLATED: a past deadline retired the old kid immediately")
	}
	// And it stays verifiable for a healthy slice of the floor window.
	time.Sleep(120 * time.Millisecond)
	if !validates(issB, oldTok) {
		t.Fatal("FAIL-SAFE VIOLATED: old kid retired before the clamp floor elapsed")
	}
	// Eventually (after the floor) it IS retired — the deferral fired, just
	// delayed to the floor rather than executed in the past.
	if !waitUntil(2*time.Second, func() bool { return !validates(issB, oldTok) }) {
		t.Fatal("clamped deferral never fired")
	}
}

// TestCoordinatedRotation_ProductionCeilingCoversDocumentedGracePeriod is the
// regression test for a real bug: coordinatedRetireMaxDeferral was previously
// 24h, but config.KeyRotationConfig's own documented example GracePeriod is
// 168h (7d) — an honest deadline built from that grace was silently clamped
// DOWN to 24h, meaning a token signed 24-168h after rotation would hit
// "unknown kid" on any replica relying on the coordinated path, well within
// its still-valid, configured grace window. That's exactly the early-retire
// 401 this whole mechanism exists to prevent (AGENTS.md: "deferred retire
// only widens verify window, never retires early"). Proves, against the
// REAL production ceiling (no test override), that a 168h-grace deadline —
// and a deliberately longer 20-day one — both pass through UNCLAMPED.
func TestCoordinatedRotation_ProductionCeilingCoversDocumentedGracePeriod(t *testing.T) {
	t.Parallel()
	srvB, _ := newCoordServer(t, clustermemory.New(), true)
	now := time.Now()

	for _, grace := range []time.Duration{168 * time.Hour, 20 * 24 * time.Hour} {
		deadline := strconv.FormatInt(now.Add(grace).UnixNano(), 10)
		got := srvB.ClampRetireDeferralForTest(now, deadline)
		// Allow a small tolerance for time elapsed between building `now` and
		// the clamp call; anything within a second of the honest grace proves
		// it passed through unclamped rather than being capped to the old,
		// buggy 24h ceiling.
		if diff := grace - got; diff < -time.Second || diff > time.Second {
			t.Errorf("grace=%s: clamped deferral = %s, want ~%s (unclamped, not capped to 24h)", grace, got, grace)
		}
	}
}

// TestCoordinatedRotation_FailSafe_NotArmedIgnoresEvent proves a replica that
// did NOT opt into coordinated rotation ignores the Event entirely — it never
// retires a key off a received rotation Event (byte-identical to a build without
// the feature on the receive side).
func TestCoordinatedRotation_FailSafe_NotArmedIgnoresEvent(t *testing.T) {
	t.Parallel()
	srvB, issB := newCoordServer(t, clustermemory.New(), false) // NOT armed
	srvB.SetCoordinatedRetireBoundsForTest(20*time.Millisecond, time.Second)

	peer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("peer"))
	oldKID := peer.KeyID()
	if err := issB.AdoptVerifyKey(oldKID, peer.PublicKey()); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	oldTok := issueUnderKid(t, peer)

	deadline := strconv.FormatInt(time.Now().Add(10*time.Millisecond).UnixNano(), 10)
	evt := sso.BuildSigningKeyRotationEventForTest(oldKID, "new-kid", deadline, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvB.ApplyCoordinatedKeyRotationForTest(ctx, evt)

	// Give any (erroneously-armed) timer well past its deadline to fire.
	time.Sleep(150 * time.Millisecond)
	if !validates(issB, oldTok) {
		t.Fatal("an UNARMED replica acted on a coordinated rotation Event")
	}
	if n := srvB.PendingSigningRetireCountForTest(); n != 0 {
		t.Fatalf("unarmed replica armed %d retire timers, want 0", n)
	}
}

// TestCoordinatedRotation_NilBusByteIdentical proves the PUBLISH side is a pure
// no-op when no bus is wired: PublishSigningKeyRotation neither panics nor has
// any effect, and no timer is armed. (Receive-side nil-default-off is covered by
// TestCoordinatedRotation_FailSafe_NotArmedIgnoresEvent.)
func TestCoordinatedRotation_NilBusByteIdentical(t *testing.T) {
	t.Parallel()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))
	// Armed but NO bus — publish must be inert.
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithDefaultTokenStrategy(sso.TokenStrategyJWT),
		sso.WithCoordinatedKeyRotation(),
	)
	oldKID := iss.KeyID()
	newKID, err := iss.RotateKey(nil)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	// Must not panic and must do nothing observable.
	srv.PublishSigningKeyRotation(context.Background(), oldKID, newKID, time.Minute)
	if n := srv.PendingSigningRetireCountForTest(); n != 0 {
		t.Fatalf("nil-bus publish armed %d timers, want 0", n)
	}
}

// TestCoordinatedRotation_PublishCarriesDeadlineAndNewKey proves the publish
// side emits a well-formed Event: old/new kids, a now+grace deadline (unix-ns),
// and the new key's JWK material — exactly what the receive side consumes.
func TestCoordinatedRotation_PublishCarriesDeadlineAndNewKey(t *testing.T) {
	t.Parallel()
	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	srvA, issA := newCoordServer(t, bus, true)
	oldKID := issA.KeyID()
	newKID, err := issA.RotateKey(nil)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	grace := 90 * time.Second
	before := time.Now().Add(grace)
	srvA.PublishSigningKeyRotation(ctx, oldKID, newKID, grace)
	after := time.Now().Add(grace)

	var evt cluster.Event
	select {
	case evt = <-events:
	case <-time.After(2 * time.Second):
		t.Fatal("no Event published")
	}
	if evt.Kind != cluster.KindSigningKeyRotation {
		t.Fatalf("kind = %q", evt.Kind)
	}
	if evt.Payload[cluster.MetaOldKid] != oldKID || evt.Payload[cluster.MetaNewKid] != newKID {
		t.Fatalf("kids wrong: %+v", evt.Payload)
	}
	ns, err := strconv.ParseInt(evt.Payload[cluster.MetaRetireDeadline], 10, 64)
	if err != nil {
		t.Fatalf("deadline parse: %v", err)
	}
	got := time.Unix(0, ns)
	if got.Before(before.Add(-2*time.Second)) || got.After(after.Add(2*time.Second)) {
		t.Fatalf("deadline %v not ~= now+grace [%v,%v]", got, before, after)
	}
	// The new JWK rides along and decodes to the new kid.
	var jwk core.JWK
	if err := json.Unmarshal([]byte(evt.Payload[cluster.MetaNewJWK]), &jwk); err != nil {
		t.Fatalf("new_jwk parse: %v", err)
	}
	if jwk.Kid != newKID {
		t.Fatalf("new_jwk kid = %q want %q", jwk.Kid, newKID)
	}
}

// TestCoordinatedRotation_ShutdownCancelsPendingRetire proves a ctx cancel (a
// clean shutdown) drops every pending deferred retire WITHOUT retiring the kid —
// shutdown must never be the trigger that drops a key (fail-safe), and no timer
// leaks.
func TestCoordinatedRotation_ShutdownCancelsPendingRetire(t *testing.T) {
	t.Parallel()
	srvB, issB := newCoordServer(t, clustermemory.New(), true)
	srvB.SetCoordinatedRetireBoundsForTest(500*time.Millisecond, time.Second)

	peer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("peer"))
	oldKID := peer.KeyID()
	if err := issB.AdoptVerifyKey(oldKID, peer.PublicKey()); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	oldTok := issueUnderKid(t, peer)

	deadline := strconv.FormatInt(time.Now().Add(500*time.Millisecond).UnixNano(), 10)
	evt := sso.BuildSigningKeyRotationEventForTest(oldKID, "new-kid", deadline, "")
	ctx, cancel := context.WithCancel(context.Background())
	srvB.ApplyCoordinatedKeyRotationForTest(ctx, evt)
	if n := srvB.PendingSigningRetireCountForTest(); n != 1 {
		t.Fatalf("armed %d timers, want 1", n)
	}

	// Cancel BEFORE the deadline — the retire must be dropped, the kid kept.
	cancel()
	if !waitUntil(2*time.Second, func() bool { return srvB.PendingSigningRetireCountForTest() == 0 }) {
		t.Fatal("pending retire not drained on ctx cancel (leaked timer)")
	}
	// Past the original deadline, the kid is STILL verifiable (cancel won, not
	// the retire).
	time.Sleep(700 * time.Millisecond)
	if !validates(issB, oldTok) {
		t.Fatal("shutdown retired the old kid — fail-safe violated")
	}
}

// waitUntil polls cond until it returns true or the timeout elapses.
func waitUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}
