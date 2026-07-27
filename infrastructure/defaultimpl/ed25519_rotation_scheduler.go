package defaultimpl

import (
	"context"
	"time"
)

// RotationConfig configures the automatic signing-key rotation loop
// started by [Ed25519JWTIssuer.StartRotation].
type RotationConfig struct {
	// Interval between rotations (e.g. 90 days). <= 0 disables the loop.
	Interval time.Duration

	// GracePeriod is how long the demoted key stays verify-only before
	// it is retired from JWKS. It MUST be >= the maximum access-token
	// TTL, otherwise tokens signed just before a rotation are stranded
	// (their key disappears while they're still live). <= 0 keeps the
	// demoted key forever (operator retires it manually).
	GracePeriod time.Duration

	// OnRotate, when set, is called after each successful rotation with
	// the demoted and new kids. The seam cmd uses to emit a
	// signing_key_rotated audit event and publish a cluster.Bus reload
	// so replicas refresh their JWKS. Must not block.
	OnRotate func(oldKID, newKID string)
}

// StartRotation runs the automatic rotation loop until ctx is
// cancelled, returning a channel that closes when the loop goroutine
// exits (mirrors the cmd retention schedulers so shutdown can wait on
// it). The first rotation fires AFTER the first Interval, so a freshly
// booted issuer keeps its seeded key for a full period.
//
// Each rotation promotes a fresh key via [Ed25519JWTIssuer.RotateKey]
// and schedules the demoted key for retirement after GracePeriod.
//
// Single-issuer semantics: every replica that runs this loop rotates to
// its OWN key, so in a multi-replica cluster either run it on a single
// leader or back the issuer with a shared external (KMS) signer whose
// rotation is managed centrally. Otherwise replicas will advertise
// divergent kids.
func (j *Ed25519JWTIssuer) StartRotation(ctx context.Context, cfg RotationConfig) <-chan struct{} {
	done := make(chan struct{})
	if cfg.Interval <= 0 {
		close(done)
		return done
	}
	go func() {
		defer close(done)
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				j.rotateTick(ctx, cfg)
				// Cancellation can arrive during key generation or OnRotate.
				// Do not consume a queued tick after that in-flight work returns.
				if ctx.Err() != nil {
					return
				}
			}
		}
	}()
	return done
}

// rotateTick runs one rotation tick, recovering from a panic in RotateKey or
// the operator-supplied OnRotate hook. This loop runs unattended for the
// server's lifetime (often months between ticks) — a misbehaving hook must
// degrade to a skipped tick, never crash the whole process. No logging here
// mirrors this loop's existing convention: a RotateKey error already skips
// the tick silently (see below), and this scheduler has no logger to call.
func (j *Ed25519JWTIssuer) rotateTick(ctx context.Context, cfg RotationConfig) {
	defer func() { _ = recover() }()
	oldKID := j.KeyID()
	newKID, err := j.RotateKey(nil)
	if err != nil {
		// crypto/rand failure is the only path here; skip this
		// tick and try again next interval rather than tearing
		// down the loop.
		return
	}
	if cfg.OnRotate != nil {
		cfg.OnRotate(oldKID, newKID)
	}
	j.scheduleRetire(ctx, oldKID, cfg.GracePeriod)
}

// scheduleRetire retires kid after grace, unless ctx is cancelled
// first. grace <= 0 means "never auto-retire" (the demoted key lingers
// until manual RetireKey or restart).
func (j *Ed25519JWTIssuer) scheduleRetire(ctx context.Context, kid string, grace time.Duration) {
	if grace <= 0 {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		t := time.NewTimer(grace)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			_ = j.RetireKey(kid)
		}
	}()
}
