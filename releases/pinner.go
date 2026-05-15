package releases

import "context"

// Pinner deploys a Release. The two methods exist so the Pinner can
// encode the asymmetric ordering operators have to live with —
// backend-first on a forward pin (frontend tolerates old API better
// than the reverse), frontend-first on a rollback (so the old UI
// stops issuing new API calls before the API itself reverts). Each
// implementation owns the ordering for its deploy mechanism so
// operators don't have to remember.
//
// Implementations live in pinner/*. Apply may take seconds (running a
// shell command, hitting an API, swapping a symlink); callers should
// pass a context with a sensible timeout.
type Pinner interface {
	// PinForward applies target as the new "current" release. Used by
	// Registry.Pin for forward releases. Returning an error aborts the
	// pin — the Registry will not advance the current pointer.
	PinForward(ctx context.Context, target *Release) error
	// PinRollback applies target as the new "current" release in
	// rollback mode. Used by Registry.Rollback. Implementations
	// SHOULD reverse the ordering they use in PinForward.
	PinRollback(ctx context.Context, target *Release) error
}
