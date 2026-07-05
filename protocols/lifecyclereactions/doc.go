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
// The one reference reaction here (RevokeAccessOnArchive) needs
// oauth.RefreshTokenSubjectIndex (protocols/oauth) alongside
// core.SessionManager and core.ClientStore (shared/core). protocols/oauth
// and protocols/caep were both already at their per-directory file-count
// budget when this feature was built (see directory_fanout_test.go), and
// protocols/caep additionally already imports protocols/oauth for its own
// StoreRevoker — importing protocols/caep back from protocols/oauth (or vice
// versa) to reuse StoreRevoker would create an import cycle. A small new
// package sits alongside both without disturbing either.
//
// RevokeAccessOnArchive therefore composes core.SessionManager /
// oauth.RefreshTokenSubjectIndex / core.ClientStore directly — the SAME
// three SPIs protocols/caep.StoreRevoker and protocols/compliance.Eraser
// each already compose independently for their own "kill all access to this
// subject" step. This is a third, small, self-contained instance of that
// same established pattern, not a new one.
//
// # Wiring (entirely opt-in; requires no interfaces/sso change)
//
//	bus := userlifecycle.NewLifecycleEventBus()
//	bus.OnUserArchived(lifecyclereactions.RevokeAccessOnArchive(sessions, refresh, clients))
//	recorder.AddSink(bus) // the same AddSink seam webhook.Engine / caep.Transmitter use
//	srv := sso.NewServer(sso.WithAuditRecorder(recorder), sso.WithUserLifecycle(store), ...)
//
// A LifecycleEventBus with zero registered reactions (the default) is a
// no-op; never calling this package at all is zero behavior change.
package lifecyclereactions
