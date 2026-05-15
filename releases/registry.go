package releases

import (
	"context"
	"errors"
	"fmt"
)

// Registry layers Pin / Rollback / Current on top of a ReleaseStore.
// The Pinner is invoked first; only if it returns nil does the Store
// advance the "current" pointer — that way a half-failed deploy
// doesn't leave the system reporting a release that didn't actually
// flip.
//
// All fields are required except Pinner: nil Pinner means "advance
// the current pointer but skip the deploy step". Useful in tests and
// when the operator uses the Pin RPC purely as a record-keeping
// signal (the actual deploy is driven by something else).
type Registry struct {
	Store  ReleaseStore
	Pinner Pinner // optional
}

// PinMode tells implementations + observers whether a Pin is moving
// forward to a newer release or rolling back to a known-good one.
type PinMode int

const (
	PinForward PinMode = iota
	PinRollback
)

func (m PinMode) String() string {
	switch m {
	case PinForward:
		return "forward"
	case PinRollback:
		return "rollback"
	default:
		return "unknown"
	}
}

// PinReport is the per-call outcome. Mirrored 1:1 to the proto
// RestoreReport-equivalent in admin/v1/releases.proto.
type PinReport struct {
	ReleaseID  string
	Mode       PinMode
	PreviousID string // "" when nothing was pinned before
}

// Pin marks id as the current release in forward mode. Schema
// regression vs the current release returns ErrSchemaRegress —
// operators must use Rollback for that direction explicitly.
func (r *Registry) Pin(ctx context.Context, id string) (*PinReport, error) {
	return r.apply(ctx, id, PinForward)
}

// Rollback marks id as the current release in rollback mode. Schema
// regression is permitted.
func (r *Registry) Rollback(ctx context.Context, id string) (*PinReport, error) {
	return r.apply(ctx, id, PinRollback)
}

// Current returns the currently-pinned release, or ErrNoCurrent when
// nothing is pinned (fresh deployments).
func (r *Registry) Current(ctx context.Context) (*Release, error) {
	if r.Store == nil {
		return nil, errors.New("releases: Registry.Store not configured")
	}
	return r.Store.Current(ctx)
}

func (r *Registry) apply(ctx context.Context, id string, mode PinMode) (*PinReport, error) {
	if r.Store == nil {
		return nil, errors.New("releases: Registry.Store not configured")
	}
	target, err := r.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var prevID string
	prev, err := r.Store.Current(ctx)
	if err != nil && !errors.Is(err, ErrNoCurrent) {
		return nil, fmt.Errorf("releases: read current: %w", err)
	}
	if prev != nil {
		prevID = prev.ID
		if mode == PinForward && target.SchemaVersion < prev.SchemaVersion {
			return nil, ErrSchemaRegress
		}
	}

	if r.Pinner != nil {
		var perr error
		switch mode {
		case PinForward:
			perr = r.Pinner.PinForward(ctx, target)
		case PinRollback:
			perr = r.Pinner.PinRollback(ctx, target)
		}
		if perr != nil {
			return nil, fmt.Errorf("releases: pinner %s: %w", mode, perr)
		}
	}

	if err := r.Store.SetCurrent(ctx, id); err != nil {
		return nil, fmt.Errorf("releases: set current: %w", err)
	}
	return &PinReport{ReleaseID: id, Mode: mode, PreviousID: prevID}, nil
}
