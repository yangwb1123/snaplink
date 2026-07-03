package rotation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/core/corecredential"
)

// ErrUnknownCredentialType is returned by Compromise for a credential class
// that was never registered with the Registry — the admin surface maps it to a
// 404 (the caller is an authorized admin, so revealing which classes exist is
// not an oracle leak).
var ErrUnknownCredentialType = errors.New("sso: rotation: unknown credential type")

// CompromiseResult reports the outcome of an emergency compromise. Governance
// metadata only — NEVER secret material, so it is safe to return from the admin
// endpoint.
type CompromiseResult struct {
	// New is the freshly-installed active version that replaced the leaked one.
	New corecredential.CredentialMeta
	// Compromised is the previously-active version now marked compromised.
	// Zero-valued (Version 0) when the class had no known active version yet
	// (a compromise declared before the first rotation/seed).
	Compromised corecredential.CredentialMeta
}

// Compromise is the emergency compromise-response path (spec Direction 2 Phase
// 3): it force-rotates credType OFF schedule, marks the leaked version
// compromised, and — UNLIKE a routine rotation — keeps NO overlap window, so the
// leaked secret is retired from the verify set the instant the replacement is
// installed. Safe to call concurrently with the scheduler's sweep loop (the
// registry state transition is mutex-guarded).
//
// Errors: ErrUnknownCredentialType (class not registered),
// corecredential.ErrCompromiseUnsupported (the class's rotator cannot instantly
// retire its secret), or a wrapped RotateCompromised error (minting the
// replacement failed — the old credential keeps serving, so the caller should
// surface a 500 and let the operator retry).
func (s *Scheduler) Compromise(ctx context.Context, credType corecredential.CredentialType, reason string) (CompromiseResult, error) {
	rotator, ok := s.reg.rotatorFor(credType)
	if !ok {
		return CompromiseResult{}, ErrUnknownCredentialType
	}
	cr, ok := rotator.(corecredential.CompromiseRotator)
	if !ok {
		return CompromiseResult{}, corecredential.ErrCompromiseUnsupported
	}
	meta, err := cr.RotateCompromised(ctx)
	if err != nil {
		s.metrics.ObserveCredentialRotation(string(credType), metrics.OutcomeFailure)
		s.logger.Error("credential compromise rotation failed — previous credential keeps serving",
			"type", string(credType), "error", err)
		return CompromiseResult{}, fmt.Errorf("rotation: compromise %q: %w", credType, err)
	}
	now := time.Now()
	compromised, retired, next, _ := s.reg.applyCompromise(credType, meta, now)
	s.persistCompromise(ctx, meta, compromised, retired)
	s.metrics.ObserveCredentialRotation(string(credType), metrics.OutcomeSuccess)
	s.notify(ctx, rotator, meta, true, reason)
	s.emit(Event{Type: credType, Outcome: EventCompromised, Meta: meta, NextDue: next, Reason: reason})
	return CompromiseResult{New: meta, Compromised: derefMeta(compromised)}, nil
}

// persistCompromise projects the compromise into the governance status store:
// the new active version plus the compromised (and any force-retired) old
// versions, each carrying the status applyCompromise stamped. Upsert (not
// UpdateStatus) so a version the store never saw is still recorded with its
// terminal status. Fail-open — the rotation already happened.
func (s *Scheduler) persistCompromise(ctx context.Context, active corecredential.CredentialMeta, compromised, retired *corecredential.CredentialMeta) {
	if s.store == nil {
		return
	}
	for _, m := range []*corecredential.CredentialMeta{&active, compromised, retired} {
		if m == nil {
			continue
		}
		if err := s.store.Upsert(ctx, *m); err != nil {
			s.logger.Error("credential compromise status upsert failed",
				"type", string(m.Type), "status", string(m.Status), "error", err)
		}
	}
}

// derefMeta returns *m or the zero value when m is nil.
func derefMeta(m *corecredential.CredentialMeta) corecredential.CredentialMeta {
	if m == nil {
		return corecredential.CredentialMeta{}
	}
	return *m
}
