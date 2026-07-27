// Package noop is a Pinner that records the call and returns nil.
// Useful for tests, dry-run smoke testing, and bootstrap setups
// where the operator wants the audit trail + current-pointer
// management without yet wiring a real deploy mechanism.
package noop

import (
	"context"

	"github.com/yangwb1123/snaplink/platform/releases"
)

// Pinner is a no-op releases.Pinner. Logger (when set) gets one line
// per call so operators can confirm the Registry is reaching the
// Pinner; production setups using a real Pinner won't see this.
type Pinner struct {
	Logger func(msg string, kv ...any)
}

func (p Pinner) log(msg, mode, id string) {
	if p.Logger != nil {
		p.Logger(msg, "mode", mode, "release_id", id)
	}
}

func (p Pinner) PinForward(_ context.Context, target *releases.Release) error {
	p.log("noop pinner", "forward", target.ID)
	return nil
}

func (p Pinner) PinRollback(_ context.Context, target *releases.Release) error {
	p.log("noop pinner", "rollback", target.ID)
	return nil
}

// Compile-time interface check.
var _ releases.Pinner = Pinner{}
