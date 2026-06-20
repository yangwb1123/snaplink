// Package none is the explicit "no encryption" snapshot.Sealer. Pipeline
// already substitutes a no-op when Sealer is nil; this package gives
// callers a typed value to pass when they want to make the choice
// visible at the call site (e.g. in CLIs and config parsing).
package none

import "github.com/snaplink/sso/interfaces/snapshot"

// Sealer leaves snapshots unencrypted. Body bytes are returned as-is.
type Sealer struct{}

// New returns a value-typed Sealer. Passing nil to a Pipeline has the
// same effect, but New() makes the intent self-documenting.
func New() Sealer { return Sealer{} }

func (Sealer) Algorithm() string { return snapshot.EncryptionNone }

func (Sealer) Seal(plain []byte) ([]byte, []byte, error) {
	out := make([]byte, len(plain))
	copy(out, plain)
	return out, nil, nil
}

func (Sealer) Open(cipher []byte, _ []byte) ([]byte, error) {
	out := make([]byte, len(cipher))
	copy(out, cipher)
	return out, nil
}

// Compile-time interface check.
var _ snapshot.Sealer = Sealer{}
