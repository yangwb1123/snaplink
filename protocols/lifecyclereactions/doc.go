// Package lifecyclereactions provides reference, OPT-IN reactions for
// domains/userlifecycle's LifecycleEventBus that need SPIs the bus mechanism
// itself cannot depend on without breaking the cognitive-layer import
// direction (ADR-0006 / architecture_layer_test.go): domains (rank 2) may
// not import protocols (rank 3), so LifecycleEventBus stays generic —
// keyed by userlifecycle.State, oblivious to any concrete SPI — inside
// domains/userlifecycle, and this package supplies concrete reactions built
// from protocols-layer types instead.
//
// # Why this is a separate package rather than added to an existing one
//
// The reference reactions here need oauth.RefreshTokenSubjectIndex
// (protocols/oauth) alongside core.SessionManager (shared/core). protocols/oauth
// and protocols/caep were both already at their per-directory file-count
// budget when this feature was built (see directory_fanout_test.go), and
// protocols/caep additionally already imports protocols/oauth for its own
// StoreRevoker — importing protocols/caep back from protocols/oauth (or vice
// versa) to reuse StoreRevoker would create an import cycle. A small new
// package sits alongside both without disturbing either.
//
// RevokeAccess therefore composes core.SessionManager and
// oauth.RefreshTokenSubjectIndex directly — the SAME SPIs
// protocols/caep.StoreRevoker and protocols/compliance.Eraser
// each already compose independently for their own "kill all access to this
// subject" step. This is a third, small, self-contained instance of that
// same established pattern, not a new one.
//
// # Wiring
//
//	bus := userlifecycle.NewLifecycleEventBus()
//	revoke := lifecyclereactions.RevokeAccess(sessions, refresh)
//	bus.OnUserSuspended(revoke)
//	bus.OnUserArchived(revoke)
//	observed := userlifecycle.ObserveTransitions(store, func(ctx context.Context, userID string, t userlifecycle.Transition) {
//		bus.Dispatch(ctx, userID, t.To)
//	})
//	srv := sso.NewServer(sso.WithUserLifecycle(observed), ...)
//
// ObserveTransitions dispatches only after a successful store append, so the
// security side effect follows the committed state. The stock sso-server wires
// every non-active state this way. SDK embedders opt in by composing the wrapper;
// a LifecycleEventBus with zero reactions is a no-op.
package lifecyclereactions
