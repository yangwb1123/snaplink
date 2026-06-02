package sso

import "github.com/snaplink/sso/signingkeys"

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
