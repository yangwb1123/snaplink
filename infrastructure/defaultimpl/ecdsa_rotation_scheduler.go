package defaultimpl

import (
	"context"
	"time"
)

// StartRotation runs the automatic rotation loop for the ES256 issuer
// until ctx is cancelled, returning a channel that closes when the loop
// goroutine exits. Mirrors [Ed25519JWTIssuer.StartRotation] exactly
// (shared RotationConfig): the first rotation fires AFTER the first
// Interval, each rotation promotes a fresh P-256 key via RotateKey and
// schedules the demoted key for retirement after GracePeriod.
//
// Single-issuer semantics apply (see the Ed25519 doc): in a multi-replica
// cluster run this on a single leader or back the issuer with a shared
// external signer, otherwise replicas advertise divergent kids.
func (j *ECDSAJWTIssuer) StartRotation(ctx context.Context, cfg RotationConfig) <-chan struct{} {
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
			}
		}
	}()
	return done
}

// rotateTick runs one rotation tick, recovering from a panic in RotateKey or
// the operator-supplied OnRotate hook — see [Ed25519JWTIssuer.rotateTick]'s
// doc for why (this loop runs unattended for the server's lifetime).
func (j *ECDSAJWTIssuer) rotateTick(ctx context.Context, cfg RotationConfig) {
	defer func() { _ = recover() }()
	oldKID := j.KeyID()
	newKID, err := j.RotateKey(nil)
	if err != nil {
		// crypto/rand failure: skip this tick rather than
		// tearing down the loop.
		return
	}
	if cfg.OnRotate != nil {
		cfg.OnRotate(oldKID, newKID)
	}
	j.scheduleRetire(ctx, oldKID, cfg.GracePeriod)
}

// scheduleRetire retires kid after grace unless ctx is cancelled first.
// grace <= 0 means "never auto-retire".
func (j *ECDSAJWTIssuer) scheduleRetire(ctx context.Context, kid string, grace time.Duration) {
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
